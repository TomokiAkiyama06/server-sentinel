import test from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { compile } from './compile.mjs';

await compile('src/i18n.ts', 'build/i18n.mjs');
await compile('tests/offline_notice_entry.ts', 'build/offline_notice.mjs');
const { messages } = await import('../build/i18n.mjs');
const {
  ApiError, CAMERA_OFFLINE_NOTICE_PATH, CAMERA_OFFLINE_NOTICE_REFRESH_MS, CameraOfflineNotice,
  createDashboardServices, parseCameraOfflineNotice, startOfflineNoticeSampling,
} = await import('../build/offline_notice.mjs');

// Issue #301 item 2. Synthetic only: no deployment, camera or person value.
const origin = 'https://server-sentinel.test';
const csrf = 'A'.repeat(42) + 'b';
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
const signal = () => new AbortController().signal;
const render = (element) => renderToStaticMarkup(element).replaceAll('&#x27;', "'").replaceAll('&quot;', '"');
const KEYS = ['cameraOfflineUnnotifiedTitle', 'cameraOfflineUnnotified', 'cameraOfflineUnnotifiedHint',
  'cameraOfflineNoticeUnavailable'];

function fake(routes) {
  const calls = [];
  const request = async (url, init) => {
    const parsed = new URL(url);
    const key = `${init.method} ${parsed.pathname}`;
    calls.push({ key, url: parsed, init });
    const answer = routes[key];
    if (!answer) return new Response('synthetic private detail', { status: 404 });
    const value = typeof answer === 'function' ? answer() : answer;
    return value instanceof Response ? value.clone() : value;
  };
  return { calls, request };
}

async function signedIn(routes = {}) {
  const transport = fake({ 'GET /api/session': json({ csrf, role: 'owner', permissions: [] }), ...routes });
  const services = createDashboardServices(origin, transport.request);
  await services.loadSession(signal());
  return { services, calls: transport.calls };
}

const rejectsWith = (promise, code) => assert.rejects(promise, error => error instanceof ApiError && error.code === code);

test('the notice decodes exactly one boolean and fails closed on anything else', () => {
  assert.equal(parseCameraOfflineNotice({ offline_unnotified: true }), true);
  assert.equal(parseCameraOfflineNotice({ offline_unnotified: false }), false);
  // Only the documented field is read.
  assert.equal(parseCameraOfflineNotice({ offline_unnotified: true, source_id: 'x', slack: 'y' }), true);
  for (const body of [null, [], 'true', true, {}, { offline_unnotified: null }, { offline_unnotified: 0 },
    { offline_unnotified: 1 }, { offline_unnotified: 'false' }, { offline_unnotified: [] }, { unnotified: true }]) {
    assert.throws(() => parseCameraOfflineNotice(body),
      error => error instanceof ApiError && error.code === 'invalid_response', JSON.stringify(body));
  }
});

test('the provider reads the Owner route same-origin without CSRF and maps refusals', async () => {
  const route = `GET ${CAMERA_OFFLINE_NOTICE_PATH}`;
  assert.equal(CAMERA_OFFLINE_NOTICE_PATH, '/api/monitoring/camera-offline');
  const { services, calls } = await signedIn({ [route]: json({ offline_unnotified: true }) });
  assert.equal(await services.loadCameraOfflineNotice(signal()), true);
  const call = calls.find(item => item.key === route);
  assert.equal(call.url.search, '');
  assert.equal(call.init.credentials, 'same-origin');
  assert.equal(call.init.mode, 'same-origin');
  assert.equal(call.init.cache, 'no-store');
  assert.equal(call.init.redirect, 'error');
  assert.equal(call.init.headers['X-CSRF-Token'], undefined);
  assert.equal(call.init.body, undefined);

  // The generic refusal (a non-Owner, or no reader mounted) is `unauthorized`.
  await rejectsWith((await signedIn()).services.loadCameraOfflineNotice(signal()), 'unauthorized');
  await rejectsWith((await signedIn({ [route]: json({}, 500) })).services.loadCameraOfflineNotice(signal()),
    'unavailable');
  await rejectsWith((await signedIn({ [route]: json({ offline_unnotified: 'true' }) }))
    .services.loadCameraOfflineNotice(signal()), 'invalid_response');
  await rejectsWith((await signedIn({ [route]: new Response('{"offline_unnotified":true}',
    { status: 200, headers: { 'Content-Type': 'text/plain' } }) })).services.loadCameraOfflineNotice(signal()),
  'invalid_response');
});

test('the notice is shown only for an unnotified offline, and a failed check is said so', () => {
  for (const locale of ['ja', 'en']) {
    const t = messages[locale];
    const shown = render(createElement(CameraOfflineNotice, { t, notice: { state: 'ready', unnotified: true } }));
    assert.match(shown, /role="alert"/);
    assert.match(shown, /data-camera-offline-unnotified="true"/);
    for (const key of ['cameraOfflineUnnotifiedTitle', 'cameraOfflineUnnotified', 'cameraOfflineUnnotifiedHint']) {
      assert.ok(shown.includes(t[key]), `${locale} ${key}`);
    }
    assert.equal(render(createElement(CameraOfflineNotice, { t, notice: { state: 'ready', unnotified: false } })), '');
    for (const state of ['pending', 'loading']) {
      assert.equal(render(createElement(CameraOfflineNotice, { t, notice: { state } })), '');
    }
    assert.equal(render(createElement(CameraOfflineNotice, { t, notice: { state: 'failed' } })),
      `<p role="status" class="muted">${t.cameraOfflineNoticeUnavailable}</p>`);
  }
});

test('every notice text exists in both locales and states facts only', () => {
  for (const locale of ['ja', 'en']) {
    for (const key of KEYS) {
      const text = messages[locale][key];
      assert.equal(typeof text, 'string', `${locale} ${key}`);
      assert.ok(text.length > 0);
      // No cause, intrusion or culprit is claimed.
      assert.doesNotMatch(text, /侵入|犯人|攻撃|盗難|intru|attack|culprit|theft|tamper/i);
    }
  }
  assert.match(messages.ja.cameraOfflineUnnotified, /通知先（Slack）が未設定/);
  assert.match(messages.en.cameraOfflineUnnotified, /No notification destination \(Slack\) is configured/);
  // The reader is the Owner: the text says what does not leave this screen,
  // not that "the administrator" is not told (PR #388 review).
  assert.match(messages.ja.cameraOfflineUnnotified, /Slack など画面の外には通知されません/);
  assert.match(messages.en.cameraOfflineUnnotified, /not notified outside this screen/);
  assert.doesNotMatch(messages.ja.cameraOfflineUnnotified, /管理者/);
  assert.doesNotMatch(messages.en.cameraOfflineUnnotified, /\bOwner\b/);
  // During a ratio (flapping) alert period the camera may be online now:
  // the hint covers both and points to the current state.
  assert.match(messages.ja.cameraOfflineUnnotifiedHint, /停止が続いているか、断続的に止まっています/);
  assert.match(messages.en.cameraOfflineUnnotifiedHint, /still stopped or has been stopping intermittently/);
  for (const locale of ['ja', 'en']) {
    assert.doesNotMatch(messages[locale].cameraOfflineUnnotifiedHint, /どのカメラがオフラインか|which camera is offline/);
  }
});

/** Manual timers: `fire()` runs the one pending callback. */
function manualTimers() {
  const pending = new Map();
  let next = 0;
  return {
    pending,
    set(run, ms) { next += 1; pending.set(next, { run, ms }); return next; },
    clear(handle) { pending.delete(handle); },
    fire() {
      assert.equal(pending.size, 1);
      const [[handle, { run }]] = pending;
      pending.delete(handle);
      run();
    },
  };
}
const settle = () => new Promise(resolve => setImmediate(resolve));

test('sampling reports each answer, refreshes after it, and a failure is reported as failed', async () => {
  assert.equal(CAMERA_OFFLINE_NOTICE_REFRESH_MS, 60000);
  const answers = [true, new Error('synthetic'), false];
  const reports = [];
  const timers = manualTimers();
  let loads = 0;
  const stop = startOfflineNoticeSampling(async () => {
    loads += 1;
    const answer = answers.shift();
    if (answer instanceof Error) throw answer;
    return answer;
  }, next => reports.push(next), { timers });
  await settle();
  assert.deepEqual(reports, [{ state: 'ready', unnotified: true }]);
  assert.equal([...timers.pending.values()][0].ms, CAMERA_OFFLINE_NOTICE_REFRESH_MS);
  timers.fire();
  await settle();
  assert.deepEqual(reports.at(-1), { state: 'failed' });
  timers.fire();
  await settle();
  assert.deepEqual(reports.at(-1), { state: 'ready', unnotified: false });
  assert.equal(loads, 3);
  stop();
  assert.equal(timers.pending.size, 0);
});

test('nothing is reported or scheduled after stop, even for a sample in flight', async () => {
  const reports = [];
  const timers = manualTimers();
  let release;
  let seen;
  const stop = startOfflineNoticeSampling(load => {
    seen = load;
    return new Promise(resolve => { release = resolve; });
  }, next => reports.push(next), { timers });
  stop();
  assert.equal(seen.aborted, true);
  release(true);
  await settle();
  assert.deepEqual(reports, []);
  assert.equal(timers.pending.size, 0);
});
