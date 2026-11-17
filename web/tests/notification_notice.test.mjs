import test from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { compile } from './compile.mjs';

await compile('src/i18n.ts', 'build/i18n.mjs');
await compile('tests/offline_notice_entry.ts', 'build/offline_notice.mjs');
const { messages } = await import('../build/i18n.mjs');
const {
  ApiError, NOTIFICATION_NOTICE_PATH, NotificationNotice, createDashboardServices, parseNotificationNotice,
  startOfflineNoticeSampling,
} = await import('../build/offline_notice.mjs');

// Issue #301 follow-up. Synthetic only: no deployment, Slack or person value.
const origin = 'https://server-sentinel.test';
const csrf = 'A'.repeat(42) + 'b';
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
const signal = () => new AbortController().signal;
const render = (element) => renderToStaticMarkup(element).replaceAll('&#x27;', "'").replaceAll('&quot;', '"');
const KEYS = ['notificationsNotConfiguredTitle', 'notificationsNotConfigured', 'notificationsNotConfiguredHint',
  'notificationsDeliveryFailedTitle', 'notificationsDeliveryFailed', 'notificationsDeliveryFailedHint',
  'notificationsNoticeUnavailable'];

function fake(routes) {
  const calls = [];
  const request = async (url, init) => {
    const parsed = new URL(url);
    const key = `${init.method} ${parsed.pathname}`;
    calls.push({ key, url: parsed, init });
    const answer = routes[key];
    if (!answer) return new Response('synthetic private detail', { status: 404 });
    return answer instanceof Response ? answer.clone() : answer;
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

test('the notice decodes one fixed cause or null and fails closed on anything else', () => {
  assert.equal(parseNotificationNotice({ cause: 'not_configured' }), 'not_configured');
  assert.equal(parseNotificationNotice({ cause: 'delivery_failed' }), 'delivery_failed');
  assert.equal(parseNotificationNotice({ cause: null }), null);
  // Only the documented field is read.
  assert.equal(parseNotificationNotice({ cause: 'not_configured', slack_webhook_url: 'x' }), 'not_configured');
  for (const body of [null, [], 'null', true, {}, { cause: undefined }, { notice: null }, { cause: 'delivered' },
    { cause: 'unverified' }, { cause: 'failed' }, { cause: '' }, { cause: 0 }, { cause: false },
    { cause: ['not_configured'] }, { cause: { value: 'not_configured' } }, { cause: 'NOT_CONFIGURED' }]) {
    assert.throws(() => parseNotificationNotice(body),
      error => error instanceof ApiError && error.code === 'invalid_response', JSON.stringify(body));
  }
});

test('the provider reads the Owner route same-origin without CSRF and maps refusals', async () => {
  const route = `GET ${NOTIFICATION_NOTICE_PATH}`;
  assert.equal(NOTIFICATION_NOTICE_PATH, '/api/monitoring/notifications');
  const { services, calls } = await signedIn({ [route]: json({ cause: 'not_configured' }) });
  assert.equal(await services.loadNotificationNotice(signal()), 'not_configured');
  const call = calls.find(item => item.key === route);
  assert.equal(call.url.search, '');
  assert.equal(call.init.credentials, 'same-origin');
  assert.equal(call.init.mode, 'same-origin');
  assert.equal(call.init.cache, 'no-store');
  assert.equal(call.init.redirect, 'error');
  assert.equal(call.init.headers['X-CSRF-Token'], undefined);
  assert.equal(call.init.body, undefined);

  // The generic refusal (a non-Owner, no reader, a state not checked) is `unauthorized`.
  await rejectsWith((await signedIn()).services.loadNotificationNotice(signal()), 'unauthorized');
  await rejectsWith((await signedIn({ [route]: json({}, 500) })).services.loadNotificationNotice(signal()),
    'unavailable');
  await rejectsWith((await signedIn({ [route]: json({ cause: 'delivered' }) }))
    .services.loadNotificationNotice(signal()), 'invalid_response');
  await rejectsWith((await signedIn({ [route]: new Response('{"cause":"not_configured"}',
    { status: 200, headers: { 'Content-Type': 'text/plain' } }) })).services.loadNotificationNotice(signal()),
  'invalid_response');
});

test('the banner is shown for either cause, and a failed check is said so', () => {
  for (const locale of ['ja', 'en']) {
    const t = messages[locale];
    const shown = render(createElement(NotificationNotice, { t, notice: { state: 'ready', cause: 'not_configured' } }));
    assert.match(shown, /role="alert"/);
    assert.match(shown, /data-notification-notice="true"/);
    assert.match(shown, /data-notification-cause="not_configured"/);
    for (const key of ['notificationsNotConfiguredTitle', 'notificationsNotConfigured', 'notificationsNotConfiguredHint']) {
      assert.ok(shown.includes(t[key]), `${locale} ${key}`);
    }
    assert.ok(!shown.includes(t.notificationsDeliveryFailed));
    const failed = render(createElement(NotificationNotice, { t, notice: { state: 'ready', cause: 'delivery_failed' } }));
    assert.match(failed, /role="alert"/);
    assert.match(failed, /data-notification-cause="delivery_failed"/);
    for (const key of ['notificationsDeliveryFailedTitle', 'notificationsDeliveryFailed', 'notificationsDeliveryFailedHint']) {
      assert.ok(failed.includes(t[key]), `${locale} ${key}`);
    }
    assert.ok(!failed.includes(t.notificationsNotConfigured));
    assert.equal(render(createElement(NotificationNotice, { t, notice: { state: 'ready', cause: null } })), '');
    for (const state of ['pending', 'loading']) {
      assert.equal(render(createElement(NotificationNotice, { t, notice: { state } })), '');
    }
    assert.equal(render(createElement(NotificationNotice, { t, notice: { state: 'failed' } })),
      `<p role="status" class="muted">${t.notificationsNoticeUnavailable}</p>`);
  }
});

test('every notice text exists in both locales, states facts only and carries no setting value', () => {
  for (const locale of ['ja', 'en']) {
    for (const key of KEYS) {
      const text = messages[locale][key];
      assert.equal(typeof text, 'string', `${locale} ${key}`);
      assert.ok(text.length > 0);
      assert.doesNotMatch(text, /侵入|犯人|攻撃|盗難|intru|attack|culprit|theft/i);
      assert.doesNotMatch(text, /hooks\.slack|https?:/);
      // The reader is the Owner (PR #388 review).
      assert.doesNotMatch(text, /管理者|\bOwner\b/);
    }
  }
  // The general case: every important notification, not only camera offline.
  assert.match(messages.ja.notificationsNotConfigured, /通知先（Slack）が未設定/);
  assert.match(messages.ja.notificationsNotConfigured, /カメラのオフライン、capture node の異常、ハードウェアの変更、録画の自己診断の失敗など/);
  assert.match(messages.en.notificationsNotConfigured, /No notification destination \(Slack\) is configured/);
  assert.match(messages.ja.notificationsNotConfiguredHint, /slack_webhook_url/);
  // Configured but failing: since this start, until a restart.
  assert.match(messages.ja.notificationsDeliveryFailed, /設定されていますが、Main Server の今回の起動以降に、Slack に届かなかった通知があります/);
  assert.match(messages.en.notificationsDeliveryFailed, /is configured, but since this Main Server start some notifications did not reach Slack/);
  // Claude review, PR #424: it stays until the next restart, and it never
  // asks the Owner to restart production just to clear it.
  assert.match(messages.ja.notificationsDeliveryFailedHint, /次の再起動まで残ります。表示を消すためだけに再起動する必要はありません/);
  assert.match(messages.en.notificationsDeliveryFailedHint, /there is no need to restart only to clear it/);
});

test('the shared sampling carries the notification cause', async () => {
  const reports = [];
  const pending = [];
  const stop = startOfflineNoticeSampling(async () => 'delivery_failed', next => reports.push(next),
    { timers: { set: (run, ms) => { pending.push(ms); return pending.length; }, clear() {} } });
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(reports, [{ state: 'ready', cause: 'delivery_failed' }]);
  assert.deepEqual(pending, [60000]);
  stop();
});
