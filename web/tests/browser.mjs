import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { launchChrome, pageFor } from './chrome.mjs';
import { compile } from './compile.mjs';

await compile('tests/harness.tsx', 'build/harness.js', 'browser');
const origin = 'http://server-sentinel.test';
const html = await readFile('dist/index.html', 'utf8');
const assets = new Map([
  ['/assets/app.js', [await readFile('dist/assets/app.js'), 'text/javascript']],
  ['/assets/app.css', [await readFile('dist/assets/app.css'), 'text/css']],
  ['/assets/icon.svg', [await readFile('dist/assets/icon.svg'), 'image/svg+xml']],
  ['/assets/harness.js', [await readFile('build/harness.js'), 'text/javascript']],
]);
const browser = await launchChrome();
const sizes = [
  { name: 'phone', width: 390, height: 844 },
  { name: 'Mac-sized viewport', width: 1440, height: 900 },
  { name: 'desktop', width: 1920, height: 1080 },
];
const owner = { state: 'allowed', role: 'owner', permissions: ['live:view', 'recordings:view'] };
const fixture = count => Array.from({ length: count }, (_, index) => ({
  id: `synthetic-source-${index}`, name: `生成カメラ ${index + 1}`,
  source_type: index % 2 ? 'remote_agent' : 'local_uvc', role: index % 2 ? 'custom role' : null,
  enabled: true, health: ['online', 'offline', 'degraded', 'manual_intervention_required'][index % 4],
}));
const observation = (kind, overrides = {}) => ({
  id: `generated-observation-${kind}`, kind, value: 'observed',
  occurred_at: '2026-09-21T09:00:00.000000+00:00', received_at: '2026-09-21T09:00:01.000000+00:00',
  source_id: '00000000-0000-4000-8000-00000000abcd', node_id: null, confidence: 0.8,
  quality: 'sufficient', clock_trusted: true, uncertainty_us: 0, confirmed: false,
  presence_state: null, sequence: 1, ...overrides,
});
const timelineFixture = {
  items: [
    observation('owner_entry', { confirmed: true }),
    observation('server_movement', { confirmed: true, clock_trusted: false }),
    observation('camera_health', { value: 'offline', quality: 'unknown', confidence: null, clock_trusted: false }),
    observation('person', { value: 'not_observed', quality: 'insufficient', confidence: null }),
  ],
  ordering_basis: 'received_at', ordering_degraded: true, causality: 'not_inferred',
  next_cursor: { received_at: '2026-09-21T09:00:01.000000+00:00', sequence: 1 },
};
const newerTimelineFixture = {
  items: [observation('storage', { value: 'degraded', quality: 'unknown', confidence: null, source_id: null, sequence: 2 })],
  ordering_basis: 'received_at', ordering_degraded: false, causality: 'not_inferred',
  next_cursor: { received_at: '2026-09-21T09:00:01.000000+00:00', sequence: 2 },
};
const presenceFixture = {
  snapshot: {
    state: 'PRESENT', basis: 'manual_override', override_expires_at: '2026-09-21T18:30:00.000000+00:00',
    clock_degraded: false, observation_clock_degraded: true, suppress_ordinary: true, critical_detection: 'armed',
    critical_persistence: 'armed', critical_evidence: 'armed', critical_notifications: 'armed',
    critical_paths_degraded: false, override_expiry_pending: false, pending_critical_actions: 0,
  },
  audit: [
    { sequence: 1, action: 'override_set', at: '2026-09-21T08:00:00.000000+00:00', state: 'PRESENT', target: null },
    { sequence: 2, action: 'critical_action_requeued', at: '2026-09-21T08:10:00.000000+00:00', state: null,
      target: 'evidence:00000000-0000-4000-8000-00000000abcd' },
  ],
};
const cancelledPresenceFixture = {
  snapshot: { ...presenceFixture.snapshot, state: 'UNKNOWN', basis: 'unknown', override_expires_at: null, suppress_ordinary: false },
  audit: [...presenceFixture.audit,
    { sequence: 3, action: 'override_cancelled', at: '2026-09-21T08:30:00.000000+00:00', state: 'PRESENT', target: null }],
};
let cases = 0;

async function scenario(viewport, { production = false, status = 200, session = owner, count = 1, optIn = false, sourceStatus = 200, positiveControl = false } = {}, assertions) {
  const page = await pageFor(browser, viewport);
  // Chrome applies bypass when parsing a document's policy. Set it before
  // navigation, only for the dedicated interception positive control.
  if (positiveControl) await page.command('Page.setBypassCSP', { enabled: true });
  const requests = [];
  const unexpected = [];
  const exceptions = [];
  const routeErrors = [];
  const cleanup = [
    browser.on('Runtime.exceptionThrown', (_, sessionId) => { if (sessionId === page.sessionId) exceptions.push('unhandled error'); }),
    browser.on('Network.webSocketCreated', (_, sessionId) => { if (sessionId === page.sessionId) unexpected.push('websocket'); }),
  ];
  await page.command('Page.addScriptToEvaluateOnNewDocument', { source: `
    window.__policyViolations = [];
    document.addEventListener('securitypolicyviolation', () => window.__policyViolations.push('CSP violation'));
    if (${optIn}) for (const key of ['telemetryOptIn', 'analyticsEnabled', 'crashUpload', 'trackingOptIn']) localStorage.setItem(key, 'true');
  ` });
  async function route({ requestId, request }) {
    const url = new URL(request.url);
    requests.push(url.pathname);
    async function fulfill(body, contentType, responseCode = 200) {
      await page.command('Fetch.fulfillRequest', { requestId, responseCode,
        responseHeaders: [{ name: 'Content-Type', value: contentType }], body: Buffer.from(body).toString('base64') });
    }
    if (url.origin !== origin || request.method !== 'GET') {
      unexpected.push('unexpected origin or method');
      await page.command('Fetch.failRequest', { requestId, errorReason: 'BlockedByClient' }); return;
    }
    if (url.pathname === '/') {
      await fulfill(production ? html : html.replace('/assets/app.js', '/assets/harness.js'), 'text/html'); return;
    }
    if (assets.has(url.pathname)) { await fulfill(...assets.get(url.pathname)); return; }
    if (!production && url.pathname === '/api/mock/session') {
      await fulfill(JSON.stringify(status === 200 ? session : { detail: 'synthetic private error' }), 'application/json', status); return;
    }
    if (!production && url.pathname === '/api/mock/sources') {
      await fulfill(JSON.stringify(sourceStatus === 200 ? fixture(count) : { detail: 'synthetic private error' }), 'application/json', sourceStatus); return;
    }
    if (!production && url.pathname === '/api/mock/timeline') {
      await fulfill(JSON.stringify(url.searchParams.has('after') ? newerTimelineFixture : timelineFixture),
        'application/json'); return;
    }
    if (!production && url.pathname === '/api/mock/presence') {
      await fulfill(JSON.stringify(presenceFixture), 'application/json'); return;
    }
    if (!production && url.pathname === '/api/mock/presence-cancelled') {
      await fulfill(JSON.stringify(cancelledPresenceFixture), 'application/json'); return;
    }
    unexpected.push('unexpected path');
    await page.command('Fetch.failRequest', { requestId, errorReason: 'BlockedByClient' });
  }
  cleanup.push(browser.on('Fetch.requestPaused', (params, sessionId) => {
    if (sessionId === page.sessionId) void route(params).catch(() => routeErrors.push('interception failed'));
  }));
  await page.command('Fetch.enable', { patterns: [{ urlPattern: '*' }] });
  try {
    const url = new URL(origin);
    if (optIn) for (const key of ['telemetryOptIn', 'analyticsEnabled', 'crashUpload', 'trackingOptIn']) url.searchParams.set(key, 'true');
    await page.command('Page.navigate', { url: url.href });
    await assertions(page, requests);
    await delay(100);
    assert.equal(await page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), true, 'no horizontal document overflow');
    assert.deepEqual(exceptions, [], 'no unhandled browser errors');
    assert.deepEqual(routeErrors, [], 'request interception must succeed');
    assert.deepEqual(await page.evaluate('window.__policyViolations'), [], 'no CSP-blocked reporting attempts');
    assert.doesNotMatch(await page.evaluate('document.body.innerText'), /synthetic private error/);
    if (positiveControl) {
      // Dedicated instrumentation check: bypass CSP only here so the synthetic
      // external request reaches the interceptor; interception aborts delivery.
      await page.evaluate("fetch('https://egress-probe.invalid/probe').catch(() => undefined)");
      assert.deepEqual(unexpected, ['unexpected origin or method']);
    } else assert.deepEqual(unexpected, [], 'all browser requests must be explicitly expected');
    cases++;
  } finally { cleanup.forEach(remove => remove()); await page.close(); }
}

try {
  const version = await browser.command('Browser.getVersion');
  process.stdout.write(`Browser execution: ${version.product}\n`);
  for (const { name, ...viewport } of sizes) {
    for (const optIn of [false, true]) {
      await scenario(viewport, { production: true, optIn }, async (page, requests) => {
        await page.heading('アクセスの確認が必要です');
        assert.equal(await page.evaluate('document.documentElement.lang'), 'ja');
        assert.equal(await page.evaluate("document.querySelectorAll('nav button:disabled').length"), 8);
        assert.equal(requests.some(path => path.startsWith('/api/')), false);
      });
      await scenario(viewport, { status: 500, optIn }, async page => {
        await page.heading('接続を確認できません');
        await page.evaluate("document.querySelector('.primary').click()");
        await page.heading('接続を確認できません');
      });
    }
    for (const count of [0, 1, 2, 3, 4]) {
      await scenario(viewport, { count }, async page => {
        await page.click('カメラソース');
        await page.wait(`document.querySelectorAll('[data-source-id]').length === ${count} && Boolean(document.querySelector('.source-count'))`);
        assert.equal(await page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), true, 'source collection fits viewport');
        for (const title of ['概要', 'キャプチャノード', 'ライブ', '録画', 'アクセス']) {
          await page.click(title); await page.heading(title);
          assert.equal(await page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), true, 'placeholder fits viewport');
        }
        await page.evaluate("document.querySelector('select').value = 'en'; document.querySelector('select').dispatchEvent(new Event('change', { bubbles: true }))");
        await page.heading('Access');
        assert.equal(await page.evaluate('document.documentElement.lang'), 'en');
      });
    }
    await scenario(viewport, {}, async page => {
      await page.click('タイムライン');
      await page.wait("document.querySelectorAll('[data-observation-kind]').length === 4");
      assert.equal(await page.evaluate("document.querySelectorAll('.timeline-span-degraded').length"), 1);
      const timelineText = await page.evaluate('document.body.innerText');
      assert.match(timelineText, /受信順で表示しています/);
      assert.match(timelineText, /判定できません/);
      assert.doesNotMatch(timelineText, /観測されず/);
      await page.evaluate("Array.from(document.querySelectorAll('.timeline-filter button')).find(el => el.textContent === 'critical').click()");
      await page.wait("document.querySelectorAll('[data-observation-kind]').length === 1");
      assert.equal(await page.evaluate("document.querySelector('[data-observation-kind]').dataset.observationKind"), 'server_movement');
      // A non-null cursor offers newer history; the next page ends the window.
      await page.evaluate("Array.from(document.querySelectorAll('.timeline-filter button')).find(el => el.textContent === 'すべて').click()");
      await page.wait("document.querySelectorAll('[data-observation-kind]').length === 4");
      await page.evaluate("document.querySelector('.timeline-screen > button').click()");
      await page.wait("document.querySelectorAll('[data-observation-kind]').length === 5");
      assert.equal(await page.evaluate("document.querySelector('.timeline-screen > button').textContent"), '新しい観測をさらに読み込む');
      // Repeating the same cursor reaches the tail, which keeps a re-check path.
      await page.evaluate("document.querySelector('.timeline-screen > button').click()");
      await page.wait("document.querySelector('.timeline-screen > button').textContent === '新しい観測を確認'");
      assert.equal(await page.evaluate("document.querySelectorAll('[data-observation-kind]').length"), 5);
      assert.match(await page.evaluate('document.body.innerText'), /受信済みの観測はすべて読み込みました。/);
      await page.click('プレゼンス');
      await page.wait("Boolean(document.querySelector('.presence-value'))");
      const presenceText = await page.evaluate('document.body.innerText');
      assert.match(presenceText, /手動上書きが有効です。/);
      assert.match(presenceText, /PRESENT かつ時刻が信頼できるため、通常の occupancy automation を抑制しています。/);
      assert.match(presenceText, /すべての presence state で継続します。/);
      assert.match(presenceText, /観測の受信時刻に skew または不連続が報告されています。/);
      assert.doesNotMatch(presenceText, /現在の状態の根拠となる記録の時刻信頼性/);
      assert.match(presenceText, /手動上書きを設定/);
      assert.match(presenceText, /対象: 証拠保護 \/ 観測 00000000/);
      assert.equal(await page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), true, 'timeline and presence fit viewport');
      // Provider methods are invoked on their service; a lost receiver fails here.
      // The refresh control re-reads the snapshot without leaving the view.
      await page.evaluate("document.querySelector('.presence-state button').click()");
      await page.wait("Boolean(document.querySelector('.presence-value'))");
      await page.evaluate("document.querySelector('.presence-override button').click()");
      await page.wait("document.querySelector('.presence-value').textContent === '不明'");
      const cancelledText = await page.evaluate('document.body.innerText');
      assert.match(cancelledText, /手動上書きはありません。/);
      assert.match(cancelledText, /手動上書きを取り消し/);
    });
    await scenario(viewport, { sourceStatus: 503 }, async page => {
      await page.click('カメラソース');
      await page.wait("Boolean(document.querySelector('[role=alert]'))");
      assert.equal(await page.evaluate("document.querySelectorAll('[data-source-id]').length"), 0);
    });
    for (const permissions of [[], ['live:view'], ['recordings:view'], ['live:view', 'recordings:view']]) {
      await scenario(viewport, { session: { state: 'allowed', role: 'viewer', permissions } }, async (page, requests) => {
        await page.heading('概要');
        assert.equal(await page.enabled('ライブ'), permissions.includes('live:view'));
        assert.equal(await page.enabled('録画'), permissions.includes('recordings:view'));
        // Historical timeline follows recordings:view; presence stays owner-only.
        assert.equal(await page.enabled('タイムライン'), permissions.includes('recordings:view'));
        assert.equal(await page.enabled('プレゼンス'), false);
        assert.equal(await page.enabled('アクセス'), false);
        assert.equal(requests.includes('/api/mock/sources'), false);
        assert.equal(requests.some(path => path.includes('timeline') || path.includes('presence')), false);
      });
    }
    process.stdout.write(`${name}: responsive synthetic UI and request interception passed\n`);
  }
  await scenario({ width: 390, height: 844 }, { production: true, positiveControl: true }, page => page.heading('アクセスの確認が必要です'));
  process.stdout.write(`${cases} browser scenarios passed; viewport emulation is not physical phone/Mac acceptance.\n`);
} finally { await browser.close(); }
