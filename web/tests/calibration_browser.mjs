/**
 * Chrome CDP checks of the Owner's scene calibration on the Sources view in
 * the built dashboard (Issue #205).
 *
 * Every request is intercepted and answered by a synthetic stand-in shaped
 * like the scene calibration routes, the live source list and the S3 step-up
 * routes; a Chrome virtual authenticator (CDP `WebAuthn`, CTAP2, user
 * verification) holding one generated credential performs the real browser
 * step-up ceremony. The page is served at `http://localhost`, a secure
 * context. The stand-in does not verify the signature: the real verifier is
 * the server's (`server/tests`). No camera, image or real person is involved;
 * this is not real-browser or real-camera acceptance (MANUAL_TEST.md §E/F).
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
// Synthetic only: generated identifiers and names.
const csrf = `${'A'.repeat(42)}b`;
const sourceId = '00000000-0000-4000-8000-00000000e001';
const otherId = '00000000-0000-4000-8000-00000000e002';
const at = '2026-10-22T01:02:03.123456+00:00';
const DIGEST = 'f'.repeat(64);
const credentialId = randomBytes(16);
const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const privateKeyPkcs8 = privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64');
const TEXT = {
  confirm: 'パスキーで確認して続ける',
  notPerformed: '本人確認が完了しなかったため、操作は行われていません。',
  run: 'この位置で校正',
  done: '校正しました',
  noFrame: '時間内にカメラの映像を取得できませんでした。カメラの接続を確認してください。',
  restart: '再起動後に自動で取り直した基準（未確認）',
  pending: '保存済みの校正あり（基準の取り直し待ち）',
  pendingPhase: '検知の開始を待っている間も、この表示です。',
  none: '未校正',
};
const CALIBRATE = `/api/scene/sources/${sourceId}/calibration`;

function status(calibrated) {
  return { sources: [
    { source_id: sourceId, origin: calibrated ? 'owner' : 'restart_reacquired', version: calibrated ? 3 : 2,
      calibrated_at: at, phase: 'idle', failure: null, owner_calibration_available: true, detection: 'active',
      detection_reason: 'evaluated', sha256: DIGEST, polygon: [[4, 4], [7, 4], [7, 7]] },
    { source_id: otherId, origin: 'none', version: null, calibrated_at: null, phase: 'reacquire_pending',
      failure: 'reader_changed', owner_calibration_available: false, detection: 'inactive',
      detection_reason: 'calibration_reference_unavailable' },
  ] };
}

const browser = await launchChrome();
let cases = 0;

async function scenario(name, { handlers: extra = () => ({}), verified = true } = {}, assertions) {
  const page = await pageFor(browser, { width: 390, height: 844 });
  const state = { challenges: [], statusLoads: 0, calibrated: false };
  const json = (code, value) => [code, JSON.stringify(value), 'application/json'];
  const stepUpRequired = () => [403, '{"detail":"step_up_required"}', 'application/json'];
  const handlers = {
    'GET /api/session': () => json(200, { csrf, role: 'owner', permissions: ['live:view', 'recordings:view'] }),
    'GET /api/scene/calibration': () => { state.statusLoads += 1; return json(200, status(state.calibrated)); },
    'GET /api/live/sources': () => json(200, { sources: [{ id: sourceId, name: '生成カメラ', health: 'online' }] }),
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
    if (handler && url.search === '') {
      await fulfill(...await handler(body), null); return;
    }
    unexpected.push(`${request.method} ${url.pathname}`);
    if (url.pathname.startsWith('/api/')) {
      await fulfill(404, JSON.stringify({ detail: PRIVATE }), 'application/json', null); return;
    }
    await page.command('Fetch.failRequest', { requestId, errorReason: 'BlockedByClient' });
  }
  cleanup.push(browser.on('Fetch.requestPaused', (params, sessionId) => {
    if (sessionId === page.sessionId) void route(params).catch(error => routeErrors.push(`interception failed: ${error?.message}`));
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
    async open() {
      await page.click('カメラソース');
      await page.wait("document.querySelectorAll('[data-calibration-source]').length === 2");
    },
    async confirmPosition() {
      await page.evaluate(`document.querySelector('[data-calibration-source="${sourceId}"] input[type=checkbox]').click()`);
    },
  };
  try {
    await page.navigate(`${origin}/app/`);
    await page.heading('概要');
    await assertions({ page, ui, requests, posts, state });
    await delay(100);
    assert.deepEqual(exceptions, [], 'no unhandled browser errors');
    assert.deepEqual(routeErrors, [], 'request interception must succeed');
    assert.deepEqual(unexpected, [], 'every request is expected');
    assert.deepEqual(await page.evaluate('window.__policyViolations'), [], 'no CSP violation');
    assert.deepEqual(await page.evaluate('window.__writes'), [], 'no storage or history writes');
    assert.equal(await page.evaluate('localStorage.length + sessionStorage.length'), 0);
    const text = await page.evaluate('document.body.innerText');
    assert.doesNotMatch(text, new RegExp(PRIVATE));
    // Nothing the status might carry beyond its fields reaches the screen.
    assert.equal(text.includes(DIGEST), false, 'no digest is rendered');
    assert.equal(await page.evaluate("document.querySelectorAll('#main img, #main canvas, #main video').length"), 0,
      'no image of the reference is shown');
    assert.equal(await page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), true, 'no horizontal overflow');
    for (const request of posts()) {
      assert.match(request.headers['Content-Type'] ?? request.headers['content-type'] ?? '', /^application\/json/);
      assert.equal(request.headers['X-CSRF-Token'] ?? request.headers['x-csrf-token'], csrf, `CSRF on POST ${request.path}`);
      assert.equal(request.headers.Origin ?? request.headers.origin, origin, `Origin on POST ${request.path}`);
      assert.equal(request.headers.Referer ?? request.headers.referer, undefined);
    }
    cases++;
    process.stdout.write(`calibration screen: ${name}\n`);
  } finally { cleanup.forEach(remove => remove()); await page.close(); }
}

try {
  process.stdout.write(`Browser execution: ${browser.version.product}\n`);

  await scenario('the status shows each source; a restart reference is marked unconfirmed', {}, async ({ page, ui, posts }) => {
    await ui.open();
    await ui.text('生成カメラ');
    await ui.text(TEXT.restart);
    // A source without a template carries no control.
    assert.equal(await page.evaluate(`document.querySelectorAll('[data-calibration-source="${otherId}"] button').length`), 0);
    // Issue #341: its stored calibration waits for the re-acquisition, so it
    // is shown as stored and pending, never as "not calibrated".
    await ui.text(TEXT.pending);
    const other = await page.evaluate(`document.querySelector('[data-calibration-source="${otherId}"]').textContent`);
    assert.ok(other.includes(TEXT.pendingPhase), other);
    assert.ok(!other.includes(TEXT.none), other);
    // The control needs the explicit normal-position statement first.
    assert.equal(await page.evaluate(`document.querySelector('[data-calibration-source="${sourceId}"] button').disabled`), true);
    assert.deepEqual(posts(), []);
  });

  await scenario('a stale Owner confirms with the passkey and the calibration is sent once more', {
    handlers: (json, stepUpRequired, state) => {
      let calls = 0;
      return { [`POST ${CALIBRATE}`]: () => {
        if ((calls += 1) === 1) return stepUpRequired();
        state.calibrated = true;
        return json(200, { outcome: 'calibrated', version: 3, calibrated_at: at });
      } };
    },
  }, async ({ page, ui, posts, state }) => {
    await ui.open();
    await ui.confirmPosition();
    await ui.button(TEXT.run);
    await page.wait("Boolean(document.querySelector('[role=alertdialog]'))");
    await delay(200);
    assert.equal(posts().length, 1);
    await ui.button(TEXT.confirm);
    await ui.text(TEXT.done);
    assert.deepEqual(posts().map(item => item.path), [CALIBRATE, '/api/auth/step-up/options', '/api/auth/step-up', CALIBRATE]);
    assert.deepEqual(JSON.parse(posts()[0].body), { normal_position_confirmed: true });
    assert.deepEqual(JSON.parse(posts()[3].body), { normal_position_confirmed: true });
    const assertion = JSON.parse(posts()[2].body);
    assert.equal(assertion.id, b64(credentialId));
    const client = JSON.parse(Buffer.from(assertion.response.clientDataJSON, 'base64url'));
    assert.equal(client.challenge, state.challenges[0]);
    // The status is loaded again and shows the Owner's calibration.
    await page.wait(`document.querySelector('[data-calibration-source="${sourceId}"]').dataset.calibrationOrigin === 'owner'`);
    assert.ok(state.statusLoads >= 2);
  });

  await scenario('a refused calibration says why and nothing more is sent', {
    handlers: json => ({ [`POST ${CALIBRATE}`]: () => json(200, { outcome: 'refused', reason: 'no_frame' }) }),
  }, async ({ ui, posts }) => {
    await ui.open();
    await ui.confirmPosition();
    await ui.button(TEXT.run);
    await ui.text(TEXT.noFrame);
    await delay(200);
    assert.deepEqual(posts().map(item => item.path), [CALIBRATE]);
  });

  await scenario('a declined step-up sends nothing more and says nothing changed', {
    handlers: (json, stepUpRequired) => ({ [`POST ${CALIBRATE}`]: stepUpRequired }),
  }, async ({ page, ui, posts }) => {
    await ui.open();
    await ui.confirmPosition();
    await ui.button(TEXT.run);
    await page.wait("Boolean(document.querySelector('[role=alertdialog]'))");
    await ui.button('やめる');
    await ui.text(TEXT.notPerformed);
    assert.deepEqual(posts().map(item => item.path), [CALIBRATE]);
  });

  await scenario('a failed ceremony is not retried and the calibration is not resent', {
    verified: false,
    handlers: (json, stepUpRequired) => ({ [`POST ${CALIBRATE}`]: stepUpRequired }),
  }, async ({ ui, posts }) => {
    await ui.open();
    await ui.confirmPosition();
    await ui.button(TEXT.run);
    await ui.button(TEXT.confirm);
    await ui.text(TEXT.notPerformed);
    assert.deepEqual(posts().map(item => item.path), [CALIBRATE, '/api/auth/step-up/options']);
  });

  process.stdout.write(`${cases} calibration screen scenarios passed; a virtual authenticator is not a real passkey provider.\n`);
} finally { await browser.close(); }
