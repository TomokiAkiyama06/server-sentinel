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
let cases = 0;

async function scenario(viewport, { production = false, status = 200, session = owner, count = 1, optIn = false, sourceStatus = 200, positiveControl = false } = {}, assertions) {
  const page = await pageFor(browser, viewport);
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
      await page.command('Page.setBypassCSP', { enabled: true });
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
        assert.equal(await page.evaluate("document.querySelectorAll('nav button:disabled').length"), 6);
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
        for (const title of ['概要', 'キャプチャノード', 'ライブ', '録画', 'アクセス']) { await page.click(title); await page.heading(title); }
        await page.evaluate("document.querySelector('select').value = 'en'; document.querySelector('select').dispatchEvent(new Event('change', { bubbles: true }))");
        await page.heading('Access');
        assert.equal(await page.evaluate('document.documentElement.lang'), 'en');
      });
    }
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
        assert.equal(await page.enabled('アクセス'), false);
        assert.equal(requests.includes('/api/mock/sources'), false);
      });
    }
    process.stdout.write(`${name}: responsive synthetic UI and request interception passed\n`);
  }
  await scenario({ width: 390, height: 844 }, { production: true, positiveControl: true }, page => page.heading('アクセスの確認が必要です'));
  process.stdout.write(`${cases} browser scenarios passed; viewport emulation is not physical phone/Mac acceptance.\n`);
} finally { await browser.close(); }
