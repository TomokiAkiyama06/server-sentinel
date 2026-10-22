/**
 * Chrome CDP checks of the Owner access screen and the step-up ceremony in
 * the built dashboard (Issue #10 phase 2 S6).
 *
 * Every request is intercepted and answered by a synthetic stand-in shaped
 * like the S4b routes A1-A6 and the S3 step-up routes; a Chrome virtual
 * authenticator (CDP `WebAuthn`, CTAP2, user verification) holding one
 * generated credential performs the real browser step-up ceremony. The page
 * is served at `http://localhost`, a secure context. The stand-in checks the
 * client data (type, challenge, origin) but not the signature: the real
 * verifier is the server's (`server/tests`). This is not real Safari, Android
 * or passkey-provider acceptance; that stays in MANUAL_TEST.md.
 */
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { launchChrome, pageFor } from './chrome.mjs';
import { APP_CSP } from '../scripts/policy.mjs';

const origin = 'http://localhost';
const files = new Map([
  ['/app/', [await readFile('dist/app/index.html'), 'text/html; charset=utf-8', APP_CSP]],
  ['/app/app.js', [await readFile('dist/app/app.js'), 'text/javascript; charset=utf-8', null]],
  ['/app/app.css', [await readFile('dist/app/app.css'), 'text/css; charset=utf-8', null]],
  ['/app/icon.svg', [await readFile('dist/app/icon.svg'), 'image/svg+xml', null]],
]);
const PRIVATE = 'synthetic private error';
const b64 = bytes => Buffer.from(bytes).toString('base64url');
// Synthetic only: generated identifiers, names and code.
const csrf = `${'A'.repeat(42)}b`;
const ownerId = '00000000-0000-4000-8000-00000000c000';
const personId = '00000000-0000-4000-8000-00000000c001';
const newId = '00000000-0000-4000-8000-00000000c002';
const handle = '00000000-0000-4000-8000-00000000d001';
const CODE = '0123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ';
const at = '2026-10-22T01:02:03.123456+00:00';
const LEAK = 'synthetic-login@example.invalid';
const credentialId = randomBytes(16);
const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const privateKeyPkcs8 = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64');
const TEXT = {
  done: '変更しました。',
  notPerformed: '本人確認が完了しなかったため、操作は行われていません。',
  confirm: 'パスキーで確認して続ける',
  unknown: '操作の結果を確認できませんでした。最新の一覧で状態を確認してから、必要ならもう一度操作してください。',
};

function inventory(extra = []) {
  const credential = { handle, label: '生成ラベル', status: 'active', inconsistency_reason: null, backup_eligible: true,
    backup_state: true, created_at: at, last_used_at: at, revoked_at: null, credential_id: 'c3ludGhldGlj' };
  return { principals: [
    { id: ownerId, display_name: '生成 管理者', role: 'owner', status: 'active', created_at: at, revoked_at: null,
      permissions: ['live:view', 'recordings:view'], invitation: { pending: false, expires_at: null }, credentials: [],
      last_external_identity: LEAK },
    { id: personId, display_name: '生成 閲覧者', role: 'invited_user', status: 'active', created_at: at, revoked_at: null,
      permissions: ['live:view'], invitation: { pending: false, expires_at: null }, credentials: [credential],
      last_external_identity: LEAK },
    ...extra,
  ] };
}

const browser = await launchChrome();
let cases = 0;

async function scenario(name, { handlers: extra = () => ({}), verified = true } = {}, assertions) {
  const page = await pageFor(browser, { width: 390, height: 844 });
  const state = { challenges: [], inventoryLoads: 0 };
  const json = (status, value) => [status, JSON.stringify(value), 'application/json'];
  const stepUpRequired = () => [403, '{"detail":"step_up_required"}', 'application/json'];
  const handlers = {
    'GET /api/session': () => json(200, { csrf, role: 'owner', permissions: ['live:view', 'recordings:view'] }),
    'GET /api/admin/principals': () => { state.inventoryLoads += 1; return json(200, inventory()); },
    'POST /api/auth/step-up/options': () => {
      const challenge = b64(randomBytes(32));
      state.challenges.push(challenge);
      return json(200, { challenge, rpId: 'localhost', timeout: 5000, userVerification: 'required',
        allowCredentials: [{ type: 'public-key', id: b64(credentialId) }] });
    },
    'POST /api/auth/step-up': () => [204, '', null],
    ...extra(json, stepUpRequired, state),
  };
  const requests = [];
  const unexpected = [];
  const exceptions = [];
  const routeErrors = [];
  const abandoned = [];
  const cleanup = [
    browser.on('Runtime.exceptionThrown', (_, sessionId) => { if (sessionId === page.sessionId) exceptions.push('unhandled error'); }),
    browser.on('Network.webSocketCreated', (_, sessionId) => { if (sessionId === page.sessionId) unexpected.push('websocket'); }),
  ];
  await page.command('WebAuthn.enable', { enableUI: false });
  const { authenticatorId } = await page.command('WebAuthn.addVirtualAuthenticator', { options: {
    protocol: 'ctap2', ctap2Version: 'ctap2_1', transport: 'internal', hasResidentKey: true,
    hasUserVerification: true, isUserVerified: verified, automaticPresenceSimulation: true,
  } });
  await page.command('WebAuthn.addCredential', { authenticatorId, credential: {
    credentialId: credentialId.toString('base64'), isResidentCredential: true, rpId: 'localhost',
    privateKey: privateKeyPkcs8, userHandle: randomBytes(16).toString('base64'), signCount: 1,
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
  async function route({ requestId, request }) {
    const url = new URL(request.url);
    let body = request.postData ?? '';
    if (!body && request.postDataEntries) body = request.postDataEntries.map(entry => Buffer.from(entry.bytes ?? '', 'base64').toString()).join('');
    requests.push({ method: request.method, url: request.url, path: url.pathname, body, headers: request.headers });
    async function fulfill(responseCode, content, contentType, csp) {
      const responseHeaders = [{ name: 'Cache-Control', value: 'no-store' }];
      if (contentType) responseHeaders.push({ name: 'Content-Type', value: contentType });
      if (csp) responseHeaders.push({ name: 'Content-Security-Policy', value: csp });
      await page.command('Fetch.fulfillRequest', { requestId, responseCode, responseHeaders,
        body: Buffer.from(content).toString('base64') });
    }
    if (url.origin !== origin) {
      unexpected.push(`origin ${url.origin}`);
      await page.command('Fetch.failRequest', { requestId, errorReason: 'BlockedByClient' }); return;
    }
    if (request.method === 'GET' && files.has(url.pathname) && url.search === '') {
      await fulfill(200, ...files.get(url.pathname)); return;
    }
    const handler = handlers[`${request.method} ${url.pathname}`];
    // A handler may answer late (a promise), as a slow Main Server would. A
    // late answer to a request the page has aborted meanwhile can no longer
    // be delivered; that is recorded as abandoned, not as a harness error.
    if (handler && url.search === '') {
      const pending = handler(body);
      const answer = await pending;
      try { await fulfill(...answer, null); } catch (error) {
        if (!(pending instanceof Promise)) throw error;
        abandoned.push(`${request.method} ${url.pathname}`);
      }
      return;
    }
    if (url.pathname.startsWith('/api/')) {
      // Anything else is the server's generic refusal (and must not be asked for).
      unexpected.push(`${request.method} ${url.pathname}`);
      await fulfill(404, JSON.stringify({ detail: PRIVATE }), 'application/json', null); return;
    }
    unexpected.push(`${request.method} ${url.pathname}`);
    await page.command('Fetch.failRequest', { requestId, errorReason: 'BlockedByClient' });
  }
  cleanup.push(browser.on('Fetch.requestPaused', (params, sessionId) => {
    if (sessionId === page.sessionId) void route(params).catch(() => routeErrors.push('interception failed'));
  }));
  await page.command('Fetch.enable', { patterns: [{ urlPattern: '*' }] });
  const posts = () => requests.filter(item => item.method === 'POST');
  const ui = {
    async button(label) {
      const find = `Array.from(document.querySelectorAll('#main button')).find(el => el.textContent === ${JSON.stringify(label)})`;
      await page.wait(`Boolean(${find}) && !(${find}).disabled`);
      await page.evaluate(`(${find}).click()`);
    },
    async text(value) { await page.wait(`document.body.innerText.includes(${JSON.stringify(value)})`); },
    async type(selector, value) {
      await page.evaluate(`(() => { const field = document.querySelector(${JSON.stringify(selector)});
        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
        field.focus(); setter.call(field, ${JSON.stringify(value)}); field.dispatchEvent(new Event('input', { bubbles: true })); })()`);
    },
    async open() {
      await page.click('アクセス');
      await page.wait("document.querySelectorAll('[data-principal-id]').length === 2");
    },
  };
  try {
    await page.navigate(`${origin}/app/`);
    await page.heading('概要');
    await assertions({ page, ui, requests, posts, state, authenticatorId, abandoned });
    await delay(100);
    assert.deepEqual(exceptions, [], 'no unhandled browser errors');
    assert.deepEqual(routeErrors, [], 'request interception must succeed');
    assert.deepEqual(unexpected, [], 'every request is expected');
    assert.deepEqual(await page.evaluate('window.__policyViolations'), [], 'no CSP violation');
    assert.deepEqual(await page.evaluate('window.__writes'), [], 'no storage or history writes');
    assert.equal(await page.evaluate('localStorage.length + sessionStorage.length'), 0);
    const text = await page.evaluate('document.body.innerText');
    assert.doesNotMatch(text, new RegExp(PRIVATE));
    // Owner decision D14: nothing the inventory might carry beyond its fields.
    assert.equal(text.includes(LEAK), false, 'no proxy identity is rendered');
    assert.doesNotMatch(text, /c3ludGhldGlj|00000000-0000-4000-8000-00000000d001/);
    assert.equal(await page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), true, 'no horizontal overflow');
    for (const item of [...requests.map(request => request.url), await page.evaluate('location.href')]) {
      assert.equal(decodeURIComponent(item).includes(CODE), false, 'no URL carries the code');
    }
    for (const request of posts()) {
      assert.match(request.headers['Content-Type'] ?? request.headers['content-type'] ?? '', /^application\/json/);
      assert.equal(request.headers['X-CSRF-Token'] ?? request.headers['x-csrf-token'], csrf, `CSRF on POST ${request.path}`);
      assert.equal(request.headers.Origin ?? request.headers.origin, origin, `Origin on POST ${request.path}`);
      assert.equal(request.headers.Referer ?? request.headers.referer, undefined);
    }
    cases++;
    process.stdout.write(`access screen: ${name}\n`);
  } finally { cleanup.forEach(remove => remove()); await page.close(); }
}

try {
  process.stdout.write(`Browser execution: ${browser.version.product}\n`);

  await scenario('invite shows the code once; closing it removes it', {
    handlers: json => ({ 'POST /api/admin/principals': () => json(200, { principal_id: newId, code: CODE, expires_at: at }) }),
  }, async ({ page, ui, posts, state }) => {
    await ui.open();
    // The Owner row carries no control; the invited person carries each one.
    assert.equal(await page.evaluate(`document.querySelectorAll('[data-principal-id="${ownerId}"] button').length`), 0);
    await ui.type('.access-invite input[type="text"]', '  生成 招待者  ');
    await page.evaluate("document.querySelectorAll('.access-grants input')[1].click()");
    await ui.button('招待コードを発行');
    await page.wait("document.querySelector('[data-invitation-code]')?.textContent === " + JSON.stringify(CODE));
    assert.deepEqual(posts().map(item => [item.path, JSON.parse(item.body)]),
      [['/api/admin/principals', { display_name: '生成 招待者', permissions: ['recordings:view'] }]]);
    await ui.text(TEXT.done);
    // The committed change made the list stale: it is loaded again.
    for (let attempt = 0; attempt < 100 && state.inventoryLoads < 2; attempt++) await delay(50);
    assert.ok(state.inventoryLoads >= 2, "the inventory is reloaded after the change");
    await ui.button('閉じる');
    await page.wait("document.querySelector('[data-invitation-code]') === null");
    assert.equal((await page.evaluate('document.body.innerText')).includes(CODE), false);
    // A page entering the back-forward cache drops a code still shown.
    await ui.type('.access-invite input[type="text"]', '生成 二人目');
    await ui.button('招待コードを発行');
    await page.wait("document.querySelector('[data-invitation-code]') !== null");
    await page.evaluate("window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }))");
    await page.wait("document.querySelector('[data-invitation-code]') === null");
  });

  await scenario('a stale Owner confirms with the passkey and the change is sent once more', {
    handlers: (json, stepUpRequired) => {
      let revokes = 0;
      return { [`POST /api/admin/principals/${personId}/credentials/${handle}/revoke`]: () =>
        (revokes += 1) === 1 ? stepUpRequired() : [204, '', null] };
    },
  }, async ({ page, ui, posts, state }) => {
    await ui.open();
    await ui.button('このパスキーを失効');
    await ui.button('失効を確定');
    await page.wait("Boolean(document.querySelector('[role=alertdialog]'))");
    // Nothing more is sent until the Owner answers.
    await delay(200);
    assert.equal(posts().length, 1);
    await ui.button(TEXT.confirm);
    await ui.text(TEXT.done);
    const revoke = `/api/admin/principals/${personId}/credentials/${handle}/revoke`;
    assert.deepEqual(posts().map(item => item.path), [revoke, '/api/auth/step-up/options', '/api/auth/step-up', revoke]);
    assert.deepEqual(posts().map(item => item.body), ['{}', '{}', posts()[2].body, '{}']);
    const assertion = JSON.parse(posts()[2].body);
    assert.deepEqual(Object.keys(assertion).sort(), ['id', 'rawId', 'response', 'type']);
    assert.deepEqual(Object.keys(assertion.response).sort(), ['authenticatorData', 'clientDataJSON', 'signature', 'userHandle']);
    // The session's own credential, as the server named it.
    assert.equal(assertion.id, b64(credentialId));
    const client = JSON.parse(Buffer.from(assertion.response.clientDataJSON, 'base64url'));
    assert.equal(client.type, 'webauthn.get');
    assert.equal(client.origin, origin);
    assert.equal(client.challenge, state.challenges[0]);
    // User verification flag set in the authenticator data (bit 2).
    assert.equal(Buffer.from(assertion.response.authenticatorData, 'base64url')[32] & 0x04, 0x04);
    assert.equal(await page.evaluate("document.querySelector('[role=alertdialog]') === null"), true);
  });

  await scenario('a declined step-up sends nothing more and says nothing changed', {
    handlers: (json, stepUpRequired) => ({ [`POST /api/admin/principals/${personId}/permissions`]: stepUpRequired }),
  }, async ({ page, ui, posts }) => {
    await ui.open();
    await ui.button('付与する');
    await page.wait("Boolean(document.querySelector('[role=alertdialog]'))");
    await ui.button('やめる');
    await ui.text(TEXT.notPerformed);
    assert.deepEqual(posts().map(item => [item.path, JSON.parse(item.body)]),
      [[`/api/admin/principals/${personId}/permissions`, { permission: 'recordings:view', granted: true }]]);
  });

  await scenario('a failed ceremony is not retried and the change is not resent', {
    verified: false,
    handlers: (json, stepUpRequired) => ({ [`POST /api/admin/principals/${personId}/revoke`]: stepUpRequired }),
  }, async ({ ui, posts }) => {
    await ui.open();
    await ui.button('この人のアクセスを失効');
    await ui.button('失効を確定');
    await ui.button(TEXT.confirm);
    await ui.text(TEXT.notPerformed);
    assert.deepEqual(posts().map(item => item.path),
      [`/api/admin/principals/${personId}/revoke`, '/api/auth/step-up/options']);
  });

  await scenario('pagehide while the step-up question is open reports that nothing changed', {
    handlers: (json, stepUpRequired) => ({ [`POST /api/admin/principals/${personId}/permissions`]: stepUpRequired }),
  }, async ({ page, ui, posts }) => {
    await ui.open();
    await ui.button('付与する');
    await page.wait("Boolean(document.querySelector('[role=alertdialog]'))");
    await page.evaluate("window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }))");
    await ui.text(TEXT.notPerformed);
    assert.equal(await page.evaluate("document.querySelector('[role=alertdialog]') === null"), true);
    await delay(300);
    // Refused before any commit and never resent; no step-up was started.
    assert.deepEqual(posts().map(item => item.path), [`/api/admin/principals/${personId}/permissions`]);
  });

  await scenario('pagehide during the step-up ceremony, before the retry, reports that nothing changed', {
    handlers: (json, stepUpRequired) => ({
      [`POST /api/admin/principals/${personId}/permissions`]: stepUpRequired,
      'POST /api/auth/step-up': async () => { await delay(800); return [204, '', null]; },
    }),
  }, async ({ page, ui, posts }) => {
    await ui.open();
    await ui.button('付与する');
    await ui.button(TEXT.confirm);
    // The assertion is posted and its answer is still pending: hide now.
    for (let attempt = 0; attempt < 100 && !posts().some(item => item.path === '/api/auth/step-up'); attempt++) await delay(20);
    await page.evaluate("window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }))");
    await ui.text(TEXT.notPerformed);
    await delay(1200);
    // The change itself was never resent.
    assert.deepEqual(posts().map(item => item.path), [`/api/admin/principals/${personId}/permissions`,
      '/api/auth/step-up/options', '/api/auth/step-up']);
  });

  await scenario('pagehide after the retry was sent reports an unknown result', {
    handlers: (json, stepUpRequired) => {
      let grants = 0;
      return { [`POST /api/admin/principals/${personId}/permissions`]: () => (grants += 1) === 1
        ? stepUpRequired() : delay(800).then(() => [204, '', null]) };
    },
  }, async ({ page, ui, posts }) => {
    await ui.open();
    await ui.button('付与する');
    await ui.button(TEXT.confirm);
    const path = `/api/admin/principals/${personId}/permissions`;
    for (let attempt = 0; attempt < 100 && posts().filter(item => item.path === path).length < 2; attempt++) await delay(20);
    await page.evaluate("window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }))");
    await ui.text(TEXT.unknown);
    assert.deepEqual(posts().map(item => item.path), [path, '/api/auth/step-up/options', '/api/auth/step-up', path]);
  });

  await scenario('an invitation answered after pagehide never shows its code', {
    handlers: json => ({ 'POST /api/admin/principals': async () => {
      await delay(800);
      return json(200, { principal_id: newId, code: CODE, expires_at: at });
    } }),
  }, async ({ page, ui, posts, abandoned }) => {
    await ui.open();
    await ui.type('.access-invite input[type="text"]', '生成 招待者');
    await ui.button('招待コードを発行');
    // Hidden (back-forward cache) while the request is still in flight.
    for (let attempt = 0; attempt < 100 && posts().length < 1; attempt++) await delay(20);
    await page.evaluate("window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }))");
    // The outcome is unknown, the controls are usable again, and the late answer is dropped.
    await ui.text(TEXT.unknown);
    await delay(1200);
    assert.equal(await page.evaluate("document.querySelector('[data-invitation-code]') === null"), true, 'no code is shown');
    assert.equal((await page.evaluate('document.body.innerText')).includes(CODE), false);
    assert.equal(await page.evaluate("document.querySelector('.access-invite button.primary').disabled"), false);
    // The request itself was aborted: its answer could not even be delivered.
    assert.deepEqual(abandoned, ['POST /api/admin/principals']);
  });

  await scenario('a shown code is dropped when that person is re-issued or revoked, whatever the answer', {
    handlers: json => {
      let reissues = 0;
      return {
        // The second answer is lost; the first and third carry a code.
        [`POST /api/admin/principals/${personId}/invitation`]: () => (reissues += 1) === 2
          ? [503, JSON.stringify({ detail: PRIVATE }), 'application/json'] : json(200, { code: CODE, expires_at: at }),
        [`POST /api/admin/principals/${personId}/revoke`]: () => [503, JSON.stringify({ detail: PRIVATE }), 'application/json'],
      };
    },
  }, async ({ page, ui }) => {
    await ui.open();
    const shown = "document.querySelector('[data-invitation-code]')?.textContent === " + JSON.stringify(CODE);
    // First re-issue: the new code is shown.
    await ui.button('招待コードを再発行');
    await ui.button('再発行を確定');
    await page.wait(shown);
    // A second re-issue whose answer is lost: the shown code may already be revoked, so it goes.
    await ui.button('招待コードを再発行');
    await ui.button('再発行を確定');
    await ui.text(TEXT.unknown);
    assert.equal(await page.evaluate("document.querySelector('[data-invitation-code]') === null"), true, 'no code is shown');
    // Show one again, then revoke the person with the answer lost: dropped as well.
    await ui.button('招待コードを再発行');
    await ui.button('再発行を確定');
    await page.wait(shown);
    await ui.button('この人のアクセスを失効');
    await ui.button('失効を確定');
    await ui.text(TEXT.unknown);
    assert.equal(await page.evaluate("document.querySelector('[data-invitation-code]') === null"), true, 'no code is shown');
  });

  process.stdout.write(`${cases} access screen scenarios passed; a virtual authenticator is not a real passkey provider.\n`);
} finally { await browser.close(); }
