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
const recordingFixture = count => Array.from({ length: count }, (_, index) => ({
  id: `synthetic-recording-${index}`, source_id: `synthetic-source-${index % 2}`,
  source_name: `生成カメラ ${(index % 2) + 1}`,
  kind: ['event', 'critical', 'manual'][index % 3],
  status: ['complete', 'gapped', 'active'][index % 3],
  start_ms: 1_700_000_000_000 + index * 600_000, duration_ms: 150_000 + index * 1_000,
  size_bytes: 536_870_912 * (index + 1), starred: index % 3 === 1,
  retention_days_left: index % 3 === 1 ? null : 20 - index,
}));
const storageFixture = (state, available_bytes = 21_474_836_480, faults = false) => ({
  state, recording_bytes: 64_424_509_440, starred_bytes: 10_737_418_240,
  available_bytes, reserved_bytes: 0, hard_reserve_bytes: 5_368_709_120,
  recording_limit_bytes: 85_899_345_920, critical_allowance_bytes: 2_147_483_648,
  recording_retention_days: 20, audit_retention_days: 90, agent_incident_retention_days: 60,
  slack_configured: false, daily_summary_local_time: '23:00',
  audit_delivery_failed: faults, cleanup_failed: faults,
  notification_delivery_failed: faults, notification_log_failed: faults,
});
let cases = 0;

async function scenario(viewport, { production = false, status = 200, session = owner, count = 1, optIn = false, sourceStatus = 200, positiveControl = false, recordings = 3, recordingStatus = 200, storageState = 'STORAGE_PRESSURE', storageAvailable, storageFaults = false, storageStatus = 200, mutationStatus = 200 } = {}, assertions) {
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
    if (!production && url.pathname === '/api/mock/recordings') {
      await fulfill(JSON.stringify(recordingStatus === 200 ? recordingFixture(recordings) : { detail: 'synthetic private error' }), 'application/json', recordingStatus); return;
    }
    if (!production && url.pathname === '/api/mock/mutation') {
      await fulfill(JSON.stringify(mutationStatus === 200 ? { accepted: true } : { detail: 'synthetic private error' }), 'application/json', mutationStatus); return;
    }
    if (!production && url.pathname === '/api/mock/mutation-refused') {
      await fulfill(JSON.stringify({ detail: 'synthetic private error' }), 'application/json', 503); return;
    }
    if (!production && url.pathname === '/api/mock/storage') {
      await fulfill(JSON.stringify(storageStatus === 200 ? storageFixture(storageState, storageAvailable, storageFaults) : { detail: 'synthetic private error' }), 'application/json', storageStatus); return;
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
        assert.equal(await page.evaluate("document.querySelectorAll('nav button:disabled').length"), 7);
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
        for (const title of ['概要', 'キャプチャノード', 'ライブ', '録画', 'ストレージと通知', 'アクセス']) {
          await page.click(title); await page.heading(title);
          assert.equal(await page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), true, 'each screen fits viewport');
        }
        await page.evaluate("document.querySelector('select').value = 'en'; document.querySelector('select').dispatchEvent(new Event('change', { bubbles: true }))");
        await page.heading('Access');
        assert.equal(await page.evaluate('document.documentElement.lang'), 'en');
      });
    }
    await scenario(viewport, { recordingStatus: 503, storageStatus: 503 }, async page => {
      await page.click('録画');
      await page.wait("Boolean(document.querySelector('[role=alert]'))");
      assert.equal(await page.evaluate("document.querySelectorAll('[data-recording-id]').length"), 0);
      await page.click('ストレージと通知');
      await page.wait("Boolean(document.querySelector('[role=alert]'))");
      assert.equal(await page.evaluate("document.querySelectorAll('[data-storage-state]').length"), 0);
    });
    for (const recordings of [0, 3]) {
      await scenario(viewport, { recordings }, async page => {
        await page.wait("typeof window.syntheticRecordingLoads === 'number'");
        assert.equal(await page.evaluate('window.syntheticRecordingLoads'), 0);
        await page.click('録画');
        await page.wait(`document.querySelectorAll('[data-recording-id]').length === ${recordings}`);
        assert.equal(await page.evaluate('window.syntheticRecordingLoads'), 1);
        // Re-opening replaces the snapshot instead of retaining coverage state
        // that was current only at the beginning of the session.
        await page.click('概要');
        await page.click('録画');
        for (let attempt = 0; attempt < 20 && await page.evaluate('window.syntheticRecordingLoads') < 2; attempt++) await delay(10);
        assert.equal(await page.evaluate('window.syntheticRecordingLoads'), 2);
        assert.equal(await page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), true, 'recording list fits viewport');
        assert.equal(await page.evaluate("document.querySelectorAll('#main a[href], #main a[download], video, source, iframe').length"), 0);
        if (!recordings) return;
        assert.equal(await page.evaluate("document.querySelectorAll('.row-actions').length"), recordings);
        // Every store-backed recording kind can be isolated, manual included.
        for (const [label, expected] of [['イベント', 1], ['手動録画', 1], ['critical 証拠', 1], ['★ 付き', 1], ['すべて', 3]]) {
          await page.evaluate(`Array.from(document.querySelectorAll('.filter')).find(el => el.textContent === ${JSON.stringify(label)}).click()`);
          await page.wait(`document.querySelectorAll('[data-recording-id]').length === ${expected}`);
        }
        // Active recordings are visibly in progress and never offer the store's
        // invalid delete operation; known gaps stay visible to the owner.
        assert.match(await page.evaluate("document.querySelector('[data-recording-id=\"synthetic-recording-2\"]').innerText"), /録画中/);
        assert.doesNotMatch(await page.evaluate("document.querySelector('[data-recording-id=\"synthetic-recording-2\"]').innerText"), /削除/);
        assert.match(await page.evaluate("document.querySelector('[data-recording-id=\"synthetic-recording-1\"]').innerText"), /欠落あり/);
        assert.match(await page.evaluate('document.body.innerText'), /この録画には既知の映像欠落があります/);
        // Owner deletion requires an explicit second confirmation in the same row.
        await page.evaluate("Array.from(document.querySelectorAll('[data-recording-id] button')).find(el => el.textContent === '削除').click()");
        await page.wait("Array.from(document.querySelectorAll('button')).some(el => el.textContent === '削除を確定')");
        await page.evaluate("Array.from(document.querySelectorAll('button')).find(el => el.textContent === 'やめる').click()");
        await page.wait(`document.querySelectorAll('[data-recording-id]').length === ${recordings}`);
        await page.evaluate("Array.from(document.querySelectorAll('[data-recording-id] button')).find(el => el.textContent === '削除').click()");
        // Hold the reload open so the window between the write succeeding and
        // the new list arriving is observable rather than a single frame.
        await page.evaluate("window.slowRecordingLoads(600)");
        await page.evaluate("Array.from(document.querySelectorAll('button')).find(el => el.textContent === '削除を確定').click()");
        // The success drops the list in the same commit, so the deleted row can
        // never be clicked again while its reload is still in flight.
        const deletions = await page.evaluate('window.syntheticMutations');
        await page.wait("document.querySelectorAll('[data-recording-id]').length === 0");
        await page.evaluate("Array.from(document.querySelectorAll('[data-recording-id] button')).forEach(el => el.click())");
        await page.wait(`document.querySelectorAll('[data-recording-id]').length === ${recordings - 1}`);
        assert.equal(await page.evaluate('window.syntheticMutations'), deletions);
        await page.evaluate("window.slowRecordingLoads(0)");
        // A repeated click while the write is in flight must not issue a second
        // mutation, and the row's owner controls say so.
        const before = await page.evaluate('window.syntheticMutations');
        const star = "Array.from(document.querySelectorAll('button')).find(el => el.textContent === '★ を付ける')";
        await page.evaluate(`(${star}).click()`);
        await page.wait("document.querySelectorAll('[aria-busy=\"true\"]').length === 1");
        assert.equal(await page.evaluate("Array.from(document.querySelectorAll('[aria-busy=\"true\"] .row-actions button')).every(el => el.disabled)"), true);
        await page.evaluate(`for (let i = 0; i < 3; i++) { const button = ${star}; if (button) button.click(); }`);
        // Every remaining row is starred only once this single write lands.
        await page.wait(`Array.from(document.querySelectorAll('button')).filter(el => el.textContent === '★ を外す').length === ${recordings - 1}`);
        await page.wait("document.querySelectorAll('[aria-busy=\"true\"]').length === 0");
        assert.equal(await page.evaluate('window.syntheticMutations'), before + 1);
        assert.equal(await page.evaluate("document.querySelectorAll('[aria-busy=\"true\"]').length"), 0);
        assert.equal(await page.evaluate("document.querySelectorAll('.row-actions button:disabled').length"), 0);
      });
    }
    // Replacing the provider must not leave the previous session's data on
    // screen; the replacement never resolves, so anything shown is stale.
    await scenario(viewport, { recordings: 3 }, async page => {
      await page.click('録画');
      await page.wait("document.querySelectorAll('[data-recording-id]').length === 3");
      await page.evaluate('window.switchProvider()');
      await page.wait("document.querySelectorAll('[data-recording-id]').length === 0");
      await page.heading('アクセスを確認しています');
      assert.doesNotMatch(await page.evaluate('document.body.innerText'), /生成カメラ/);
      assert.equal(await page.evaluate("document.querySelectorAll('nav button:disabled').length"), 7);
    });
    // A recovered NORMAL state must still surface sticky backend faults.
    await scenario(viewport, { storageState: 'NORMAL', storageFaults: true }, async (page, requests) => {
      assert.equal(requests.filter(path => path === '/api/mock/storage').length, 0);
      await page.click('ストレージと通知');
      await page.wait("document.querySelectorAll('[data-fault]').length === 4");
      assert.equal(requests.filter(path => path === '/api/mock/storage').length, 1);
      assert.equal(await page.evaluate("document.querySelectorAll('.fault-alert[role=alert]').length"), 2);
      assert.match(await page.evaluate('document.body.innerText'), /監査記録に書き込めませんでした/);
      assert.match(await page.evaluate('document.body.innerText'), /Slack へ通知を送信できませんでした/);
      assert.equal(await page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), true, 'fault alerts fit viewport');
      await page.click('概要');
      await page.click('ストレージと通知');
      for (let attempt = 0; attempt < 20 && requests.filter(path => path === '/api/mock/storage').length < 2; attempt++) await delay(10);
      assert.equal(requests.filter(path => path === '/api/mock/storage').length, 2);
    });
    // The operational snapshot is re-read whenever the screen is opened and on
    // demand, so a backend that later enters hard stop cannot stay hidden.
    await scenario(viewport, {}, async (page, requests) => {
      await page.click('ストレージと通知');
      await page.wait("document.querySelectorAll('[data-storage-state]').length === 3");
      const first = requests.filter(path => path === '/api/mock/storage').length;
      assert.equal(first, 1);
      await page.click('概要');
      await page.heading('概要');
      await page.click('ストレージと通知');
      // Re-entry must not paint the previous snapshot while the reload runs.
      assert.equal(await page.evaluate("document.querySelectorAll('[data-storage-state]').length"), 0);
      await page.wait("document.querySelectorAll('[data-storage-state]').length === 3");
      assert.equal(requests.filter(path => path === '/api/mock/storage').length, first + 1);
      await page.evaluate("Array.from(document.querySelectorAll('.storage button')).find(el => el.textContent === '最新の状態を取得').click()");
      // An explicit refresh does not change the view, so it must drop the
      // displayed snapshot itself instead of leaving stale health painted.
      assert.equal(await page.evaluate("document.querySelectorAll('[data-storage-state]').length"), 0);
      await delay(300);
      assert.equal(requests.filter(path => path === '/api/mock/storage').length, first + 2);
      await page.wait("document.querySelectorAll('[data-storage-state]').length === 3");
    });
    // One recording's successful write must not clear another's unknown result.
    await scenario(viewport, { recordings: 3 }, async page => {
      await page.click('録画');
      await page.wait("document.querySelectorAll('[data-recording-id]').length === 3");
      await page.evaluate("window.failNextMutations('/api/mock/mutation-refused')");
      await page.evaluate("document.querySelector('[data-recording-id=\"synthetic-recording-0\"] .row-actions button').click()");
      await page.wait("document.querySelectorAll('[data-write-failed=\"true\"]').length === 1");
      // A second failure does not replace the first: each recording keeps its
      // own unknown result, and only the failing rows are marked.
      await page.evaluate("document.querySelector('[data-recording-id=\"synthetic-recording-1\"] .row-actions button').click()");
      await page.wait("document.querySelectorAll('[data-write-failed=\"true\"]').length === 2");
      assert.deepEqual(await page.evaluate("Array.from(document.querySelectorAll('[data-write-failed=\"true\"]')).map(el => el.dataset.recordingId)"),
        ['synthetic-recording-0', 'synthetic-recording-1']);
      assert.equal(await page.evaluate("document.querySelectorAll('.write-alert').length"), 1);
      // Filtering the marked rows out of view must not hide which writes are
      // unresolved: the alert names them itself.
      await page.evaluate(`Array.from(document.querySelectorAll('.filter')).find(el => el.textContent === '★ 付き').click()`);
      await page.wait("document.querySelectorAll('[data-recording-id]').length === 1");
      assert.equal(await page.evaluate("document.querySelectorAll('[data-write-failed=\"true\"]').length"), 1);
      assert.deepEqual(await page.evaluate("Array.from(document.querySelectorAll('[data-unresolved]')).map(el => el.dataset.unresolved)"),
        ['synthetic-recording-0', 'synthetic-recording-1']);
      assert.equal(await page.evaluate("document.querySelectorAll('.write-alert').length"), 1);
      await page.evaluate(`Array.from(document.querySelectorAll('.filter')).find(el => el.textContent === 'すべて').click()`);
      await page.wait("document.querySelectorAll('[data-recording-id]').length === 3");
      // A reload cannot prove what became of a write whose response was lost,
      // so re-opening the list leaves both markers in place.
      await page.evaluate("window.failNextMutations('/api/mock/mutation')");
      await page.click('概要');
      await page.click('録画');
      await page.wait("document.querySelectorAll('[data-recording-id]').length === 3");
      assert.deepEqual(await page.evaluate("Array.from(document.querySelectorAll('[data-write-failed=\"true\"]')).map(el => el.dataset.recordingId)"),
        ['synthetic-recording-0', 'synthetic-recording-1']);
      // A later successful write to one recording is a terminal outcome the
      // client observed, so only that recording's marker is resolved.
      await page.evaluate("document.querySelector('[data-recording-id=\"synthetic-recording-0\"] .row-actions button').click()");
      await page.wait("document.querySelectorAll('[data-recording-id]').length === 3 && document.querySelectorAll('[data-write-failed=\"true\"]').length === 1");
      assert.deepEqual(await page.evaluate("Array.from(document.querySelectorAll('[data-write-failed=\"true\"]')).map(el => el.dataset.recordingId)"),
        ['synthetic-recording-1']);
      // The rest is resolved only by the owner acknowledging that they checked.
      await page.evaluate(`Array.from(document.querySelectorAll('.write-alert button')).find(el => el.textContent === '確認したので閉じる').click()`);
      await page.wait("document.querySelectorAll('.write-alert').length === 0");
      assert.equal(await page.evaluate("document.querySelectorAll('[data-write-failed=\"true\"]').length"), 0);
    });
    // A write failing while a reload is already in flight may have happened
    // after the server took its snapshot, so that reload must not answer for it.
    await scenario(viewport, { recordings: 3 }, async page => {
      await page.click('録画');
      await page.wait("document.querySelectorAll('[data-recording-id]').length === 3");
      await page.evaluate("window.slowRecordingLoads(900)");
      // recording-0 fails late; recording-1 succeeds early and starts the reload.
      await page.evaluate("window.mutationPlan({ 'synthetic-recording-0': { delay: 600, fail: true } })");
      await page.evaluate("document.querySelector('[data-recording-id=\"synthetic-recording-0\"] .row-actions button').click()");
      await page.evaluate("document.querySelector('[data-recording-id=\"synthetic-recording-1\"] .row-actions button').click()");
      await page.wait("document.querySelectorAll('[data-recording-id]').length === 3 && document.querySelectorAll('.write-alert').length === 1");
      assert.deepEqual(await page.evaluate("Array.from(document.querySelectorAll('[data-write-failed=\"true\"]')).map(el => el.dataset.recordingId)"),
        ['synthetic-recording-0']);
      await page.evaluate("window.slowRecordingLoads(0); window.mutationPlan({})");
    });
    // Retrying the same recording raises a newer failure. A reload that began
    // before that retry failed must not claim to have answered for it.
    await scenario(viewport, { recordings: 3 }, async page => {
      await page.click('録画');
      await page.wait("document.querySelectorAll('[data-recording-id]').length === 3");
      await page.evaluate("window.mutationPlan({ 'synthetic-recording-0': { fail: true } })");
      await page.evaluate("document.querySelector('[data-recording-id=\"synthetic-recording-0\"] .row-actions button').click()");
      await page.wait("document.querySelectorAll('[data-write-failed=\"true\"]').length === 1");
      // Retry the same row, then reload before that retry settles.
      await page.evaluate("window.mutationPlan({ 'synthetic-recording-0': { fail: true, delay: 700 } }); window.slowRecordingLoads(1200)");
      await page.evaluate("document.querySelector('[data-recording-id=\"synthetic-recording-0\"] .row-actions button').click()");
      await page.evaluate("document.querySelector('.write-alert .primary').click()");
      await page.wait("document.querySelectorAll('[data-recording-id]').length === 3");
      // The reload cannot answer for the retry, so its marker survives.
      assert.deepEqual(await page.evaluate("Array.from(document.querySelectorAll('[data-write-failed=\"true\"]')).map(el => el.dataset.recordingId)"),
        ['synthetic-recording-0']);
      assert.equal(await page.evaluate("document.querySelectorAll('.write-alert').length"), 1);
      await page.evaluate("window.slowRecordingLoads(0); window.mutationPlan({})");
    });
    // The reload control must not clear the markers before a reload succeeds.
    await scenario(viewport, { recordings: 3 }, async page => {
      await page.click('録画');
      await page.wait("document.querySelectorAll('[data-recording-id]').length === 3");
      await page.evaluate("window.mutationPlan({ 'synthetic-recording-0': { fail: true } })");
      await page.evaluate("document.querySelector('[data-recording-id=\"synthetic-recording-0\"] .row-actions button').click()");
      await page.wait("document.querySelectorAll('[data-write-failed=\"true\"]').length === 1");
      // Reloading and failing leaves no list, so the unknown result must still
      // be reported instead of being cleared by the attempt itself.
      await page.evaluate("window.failRecordingLoads(true)");
      await page.evaluate("document.querySelector('.write-alert .primary').click()");
      await page.wait("document.querySelectorAll('[role=alert]').length === 1 && document.querySelectorAll('[data-recording-id]').length === 0");
      assert.match(await page.evaluate('document.body.innerText'), /録画の一覧を取得できません/);
      assert.equal(await page.evaluate("document.querySelectorAll('[data-write-failed=\"true\"]').length"), 1);
      // Even a successful reload leaves it: the snapshot proves nothing about a
      // write whose response was lost. Only an acknowledgement closes it.
      await page.evaluate("window.failRecordingLoads(false); window.mutationPlan({})");
      await page.evaluate("document.querySelector('[role=alert] .primary').click()");
      await page.wait("document.querySelectorAll('[data-recording-id]').length === 3");
      assert.equal(await page.evaluate("document.querySelectorAll('[data-write-failed=\"true\"]').length"), 1);
      await page.evaluate(`Array.from(document.querySelectorAll('.write-alert button')).find(el => el.textContent === '確認したので閉じる').click()`);
      await page.wait("document.querySelectorAll('.write-alert').length === 0");
      assert.equal(await page.evaluate("document.querySelectorAll('[data-write-failed=\"true\"]').length"), 0);
    });
    // A rejected write reports itself without discarding the loaded list.
    await scenario(viewport, { recordings: 3, mutationStatus: 503 }, async page => {
      await page.click('録画');
      await page.wait("document.querySelectorAll('[data-recording-id]').length === 3");
      await page.evaluate("Array.from(document.querySelectorAll('button')).find(el => el.textContent === '★ を付ける').click()");
      await page.wait("Boolean(document.querySelector('.write-alert'))");
      assert.equal(await page.evaluate("document.querySelectorAll('[data-recording-id]').length"), 3);
      assert.equal(await page.evaluate("document.querySelectorAll('[aria-busy=\"true\"]').length"), 0);
      assert.equal(await page.evaluate("document.querySelectorAll('.row-actions button:disabled').length"), 0);
      assert.doesNotMatch(await page.evaluate('document.body.innerText'), /録画の一覧を取得できません/);
      // Reloading keeps the list and the unresolved warning; acknowledging closes it.
      await page.evaluate("document.querySelector('.write-alert .primary').click()");
      await page.wait("document.querySelectorAll('[data-recording-id]').length === 3");
      assert.equal(await page.evaluate("document.querySelectorAll('.write-alert').length"), 1);
      await page.evaluate(`Array.from(document.querySelectorAll('.write-alert button')).find(el => el.textContent === '確認したので閉じる').click()`);
      await page.wait("document.querySelectorAll('.write-alert').length === 0 && document.querySelectorAll('[data-recording-id]').length === 3");
    });
    for (const storageState of ['NORMAL', 'STORAGE_PRESSURE', 'STORAGE_HARD_STOP']) {
      await scenario(viewport, { storageState }, async page => {
        await page.click('ストレージと通知');
        await page.wait("document.querySelectorAll('[data-storage-state]').length === 3");
        await page.wait(`document.querySelector('[data-storage-state=${storageState}]').getAttribute('aria-current') === 'true'`);
        await page.wait("document.querySelectorAll('[data-retention]').length === 3");
        assert.deepEqual(await page.evaluate("Array.from(document.querySelectorAll('[data-retention] .retention-days')).map(el => el.textContent)"),
          ['20 日', '90 日', '60 日']);
        assert.equal(await page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), true, 'storage screen fits viewport');
        assert.match(await page.evaluate('document.body.innerText'), /未設定/);
        assert.match(await page.evaluate('document.body.innerText'), /23:00/);
        // An intact reserve reports no shortfall.
        assert.equal(await page.evaluate("document.querySelectorAll('[data-reserve-shortfall]').length"), 0);
        assert.equal(await page.evaluate("document.querySelectorAll('[data-fault]').length"), 0);
        assert.deepEqual(await page.evaluate("Array.from(document.querySelectorAll('meter')).map(el => el.value)"),
          [53_687_091_200, 10_737_418_240, 16_106_127_360, 5_368_709_120]);
      });
    }
    // A reserve already eaten by external filesystem use must not be shown as
    // remaining space: 1 GiB available under a 5 GiB configured reserve.
    await scenario(viewport, { storageState: 'STORAGE_HARD_STOP', storageAvailable: 1_073_741_824 }, async page => {
      await page.click('ストレージと通知');
      await page.wait("document.querySelectorAll('[data-reserve-shortfall]').length === 1");
      assert.deepEqual(await page.evaluate("Array.from(document.querySelectorAll('meter')).map(el => el.value)"),
        [53_687_091_200, 10_737_418_240, 0, 1_073_741_824]);
      assert.match(await page.evaluate('document.body.innerText'), /4\.0 GiB/);
      assert.equal(await page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), true, 'storage screen fits viewport');
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
        assert.equal(await page.enabled('アクセス'), false);
        assert.equal(await page.enabled('ストレージと通知'), false);
        if (permissions.includes('recordings:view')) {
          await page.click('録画');
          await page.wait("document.querySelectorAll('[data-recording-id]').length === 3");
          // Non-owner: no star/delete control and no download or media route.
          assert.equal(await page.evaluate("document.querySelectorAll('.row-actions').length"), 0);
          assert.equal(await page.evaluate("document.querySelectorAll('#main a[href], #main a[download], video, source, iframe').length"), 0);
        }
        assert.equal(requests.includes('/api/mock/sources'), false);
        assert.equal(requests.includes('/api/mock/storage'), false);
        assert.equal(requests.includes('/api/mock/recordings'), permissions.includes('recordings:view'));
      });
    }
    process.stdout.write(`${name}: responsive synthetic UI and request interception passed\n`);
  }
  await scenario({ width: 390, height: 844 }, { production: true, positiveControl: true }, page => page.heading('アクセスの確認が必要です'));
  process.stdout.write(`${cases} browser scenarios passed; viewport emulation is not physical phone/Mac acceptance.\n`);
} finally { await browser.close(); }
