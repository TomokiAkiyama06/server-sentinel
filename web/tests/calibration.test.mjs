import test from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { compile } from './compile.mjs';

await compile('src/i18n.ts', 'build/i18n.mjs');
await compile('tests/calibration_entry.ts', 'build/calibration.mjs');
const { messages } = await import('../build/i18n.mjs');
const {
  ApiError, calibrationReasons, createDashboardServices, parseCalibrationResult, parseSceneCalibration,
  CalibrationCard, CalibrationScreen, refusalText, SourceInventory,
} = await import('../build/calibration.mjs');

// Synthetic only: generated identifiers, no deployment, camera or person value.
const origin = 'https://server-sentinel.test';
const csrf = 'A'.repeat(42) + 'b';
const sourceId = '00000000-0000-4000-8000-00000000e001';
const otherId = '00000000-0000-4000-8000-00000000e002';
const at = '2026-10-22T01:02:03.123456+00:00';
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
const STEP_UP = () => new Response('{"detail":"step_up_required"}', {
  status: 403, headers: { 'Content-Type': 'application/json', 'Content-Length': '29' } });
const signal = () => new AbortController().signal;
const noop = () => undefined;
const render = (element) => renderToStaticMarkup(element).replaceAll('&#x27;', "'").replaceAll('&quot;', '"');

const source = (overrides = {}) => ({
  source_id: sourceId, origin: 'owner', version: 2, calibrated_at: at, phase: 'idle', failure: null,
  owner_calibration_available: true, detection: 'active', detection_reason: 'evaluated', ...overrides,
});

function fake(routes) {
  const calls = [];
  const request = async (url, init) => {
    const parsed = new URL(url);
    const key = `${init.method} ${parsed.pathname}`;
    calls.push({ key, url: parsed, init });
    const answer = routes[key];
    if (!answer) return new Response('synthetic private detail', { status: 404 });
    const value = typeof answer === 'function' ? answer(parsed, init, calls) : answer;
    return value instanceof Response ? value.clone() : value;
  };
  return { calls, request };
}

async function signedIn(routes = {}, options = {}) {
  const transport = fake({ 'GET /api/session': json({ csrf, role: 'owner', permissions: [] }), ...routes });
  const services = createDashboardServices(origin, transport.request, options);
  await services.loadSession(signal());
  return { services, calls: transport.calls };
}

test('the source inventory beside the calibration keeps its loading and failure states', () => {
  // Codex P2 / Claude review 2 (PR #330): never silently absent.
  for (const locale of ['ja', 'en']) {
    const t = messages[locale];
    for (const state of ['pending', 'loading']) {
      const html = render(createElement(SourceInventory, { t, sources: { state } }));
      assert.equal(html, `<p role="status">${t.checking}</p>`);
    }
    assert.equal(render(createElement(SourceInventory, { t, sources: { state: 'failed' } })),
      `<p role="alert">${t.sourcesUnavailable}</p>`);
    const ready = render(createElement(SourceInventory, { t, sources: { state: 'ready', items: [
      { id: sourceId, name: 'generated', source_type: 'local_uvc', role: '', health: 'online', enabled: true },
    ] } }));
    assert.match(ready, new RegExp(`data-source-id="${sourceId}"`));
    assert.doesNotMatch(ready, /role="alert"|role="status"/);
  }
});

test('status decodes strictly and copies only the documented fields', async () => {
  const body = { sources: [
    { ...source(), sha256: 'f'.repeat(64), polygon: [[1, 2]], policy: { movement_pixels: 1 }, pixels: 'AAAA' },
    source({ source_id: otherId, origin: 'none', version: null, calibrated_at: null, phase: 'reacquire_pending',
      failure: 'reader_changed', owner_calibration_available: false, detection: 'inactive',
      detection_reason: 'calibration_reference_unavailable' }),
  ] };
  const parsed = parseSceneCalibration(body);
  assert.deepEqual(parsed[0], source());
  assert.doesNotMatch(JSON.stringify(parsed), /ffff|polygon|policy|pixels|AAAA/);
  const { services, calls } = await signedIn({ 'GET /api/scene/calibration': json(body) });
  assert.equal((await services.loadSceneCalibration(signal())).length, 2);
  const call = calls.at(-1);
  assert.equal(call.url.href, `${origin}/api/scene/calibration`);
  assert.deepEqual(call.init.headers, { Accept: 'application/json' });
  assert.equal(call.init.redirect, 'error');
  assert.equal(call.init.credentials, 'same-origin');
});

test('one malformed source fails the whole status closed', () => {
  const bad = [
    null, { ...source(), source_id: 'x' }, { ...source(), source_id: sourceId.toUpperCase() },
    { ...source(), origin: 'guessed' }, { ...source(), version: 0 }, { ...source(), version: 1.5 },
    { ...source(), version: null }, { ...source(), calibrated_at: null },
    { ...source(), origin: 'none' }, { ...source(), calibrated_at: '2026-10-22 01:02:03' },
    { ...source(), phase: 'done' }, { ...source(), failure: 'other' }, { ...source(), owner_calibration_available: 1 },
    { ...source(), detection: 'unknown' }, { ...source(), detection_reason: 'Bad Reason' },
    { ...source(), detection_reason: '' },
  ];
  for (const entry of bad) {
    assert.throws(() => parseSceneCalibration({ sources: [source({ source_id: otherId }), entry] }),
      { code: 'invalid_response' }, JSON.stringify(entry));
  }
  assert.throws(() => parseSceneCalibration({ sources: [source(), source()] }), { code: 'invalid_response' });
  for (const body of [null, [], {}, { sources: {} }]) {
    assert.throws(() => parseSceneCalibration(body), { code: 'invalid_response' });
  }
});

test('a calibration result is calibrated with its version or one fixed refusal', () => {
  assert.deepEqual(parseCalibrationResult({ outcome: 'calibrated', version: 3, calibrated_at: at }),
    { outcome: 'calibrated', version: 3, calibrated_at: at });
  for (const reason of calibrationReasons) {
    assert.deepEqual(parseCalibrationResult({ outcome: 'refused', reason }), { outcome: 'refused', reason });
  }
  for (const value of [null, {}, { outcome: 'calibrated', version: 0, calibrated_at: at },
    { outcome: 'calibrated', version: 1, calibrated_at: 'now' }, { outcome: 'refused', reason: 'secret' },
    { outcome: 'done' }]) {
    assert.throws(() => parseCalibrationResult(value), { code: 'invalid_response' });
  }
});

test('calibrate posts the normal-position statement with CSRF and maps the answers', async () => {
  const path = `POST /api/scene/sources/${sourceId}/calibration`;
  const { services, calls } = await signedIn({ [path]: json({ outcome: 'calibrated', version: 1, calibrated_at: at }) });
  assert.deepEqual(await services.calibrateSource(sourceId, signal()), { outcome: 'calibrated', version: 1, calibrated_at: at });
  const call = calls.at(-1);
  assert.equal(call.init.body, JSON.stringify({ normal_position_confirmed: true }));
  assert.deepEqual(call.init.headers, { Accept: 'application/json', 'X-CSRF-Token': csrf, 'Content-Type': 'application/json' });
  assert.equal(call.init.referrer, '');
  assert.equal(call.init.referrerPolicy, 'same-origin');
  const refused = await signedIn({ [path]: json({ outcome: 'refused', reason: 'no_frame' }) });
  assert.deepEqual(await refused.services.calibrateSource(sourceId, signal()), { outcome: 'refused', reason: 'no_frame' });
  const stale = await signedIn({ [path]: STEP_UP });
  await assert.rejects(stale.services.calibrateSource(sourceId, signal()), { code: 'step_up_required' });
  const denied = await signedIn({});
  await assert.rejects(denied.services.calibrateSource(sourceId, signal()), { code: 'unauthorized' });
  await assert.rejects(denied.services.calibrateSource('../admin', signal()), { code: 'invalid_request' });
  await assert.rejects(denied.services.calibrateSource(sourceId.toUpperCase(), signal()), { code: 'invalid_request' });
  assert.ok(ApiError);
});

test('a calibration waits longer than an ordinary request, and still has a bound', async () => {
  const path = `POST /api/scene/sources/${sourceId}/calibration`;
  const late = () => new Promise(resolve => setTimeout(() => resolve(json({ outcome: 'calibrated', version: 1,
    calibrated_at: at })), 80));
  const patient = await signedIn({ [path]: late }, { requestMs: 20, calibrateMs: 1000 });
  assert.equal((await patient.services.calibrateSource(sourceId, signal())).outcome, 'calibrated');
  const hung = await signedIn({ [path]: () => new Promise(() => undefined) }, { calibrateMs: 30 });
  await assert.rejects(hung.services.calibrateSource(sourceId, signal()), { code: 'unavailable' });
});

test('a card shows origin, version, time and failure; the control needs the explicit statement', () => {
  for (const locale of ['ja', 'en']) {
    const t = messages[locale];
    const html = render(createElement(CalibrationCard, { t, item: source(), name: '生成カメラ', disabled: false,
      confirmed: false, onConfirm: noop, onCalibrate: noop }));
    for (const text of [t.calibrationOrigin_owner, t.calibrationDetection_active, '2026-10-22 01:02 UTC',
      t.calibrationConfirm, t.calibrationRun, '生成カメラ']) assert.ok(html.includes(text), text);
    assert.match(html, /type="checkbox"/);
    assert.match(html, /<button type="button" class="primary" disabled="">/);
    const confirmed = render(createElement(CalibrationCard, { t, item: source(), name: null, disabled: false,
      confirmed: true, onConfirm: noop, onCalibrate: noop }));
    assert.doesNotMatch(confirmed, /<button type="button" class="primary" disabled="">/);
    assert.ok(confirmed.includes(`${t.calibrationSourceId} 00000000`));
  }
});

test('a restart re-acquired reference warns that it was not confirmed by the Owner', () => {
  const t = messages.ja;
  const html = render(createElement(CalibrationCard, { t, item: source({ origin: 'restart_reacquired' }), name: null,
    disabled: false, confirmed: false, onConfirm: noop, onCalibrate: noop }));
  assert.ok(html.includes(t.calibrationOrigin_restart_reacquired));
  assert.ok(html.includes(t.calibrationRestartWarning));
  assert.match(t.calibrationRestartWarning, /検知できません/);
  assert.match(messages.en.calibrationRestartWarning, /not detected/);
  const pending = render(createElement(CalibrationCard, { t, item: source({ origin: 'none', version: null,
    calibrated_at: null, phase: 'reacquire_pending', failure: 'no_frame', owner_calibration_available: false,
    detection: 'inactive', detection_reason: 'calibration_reference_unavailable' }), name: null, disabled: false,
    confirmed: false, onConfirm: noop }));
  for (const text of [t.calibrationPhase_reacquire_pending, t.calibrationRefused_no_frame, t.calibrationNoTemplate,
    'calibration_reference_unavailable']) assert.ok(pending.includes(text), text);
  assert.doesNotMatch(pending, /type="checkbox"|<button/);
});

test('every refusal and calibration text exists in both locales', () => {
  for (const reason of calibrationReasons) {
    for (const locale of ['ja', 'en']) assert.ok(refusalText(messages[locale], reason), `${locale} ${reason}`);
  }
  const keys = locale => Object.keys(messages[locale]).filter(key => key.startsWith('calibration')).sort();
  assert.deepEqual(keys('ja'), keys('en'));
  // The texts never promise that the image is stored or that a person is identified.
  for (const locale of ['ja', 'en']) {
    for (const key of keys(locale)) assert.doesNotMatch(messages[locale][key], /犯人|culprit|identif(y|ied) (the|a) person/i, key);
  }
  assert.match(messages.ja.calibrationMemoryNote, /ディスクには保存しません/);
  assert.match(messages.en.calibrationMemoryNote, /never written to disk/);
});

test('the screen renders nothing without a provider and loads with one', () => {
  const t = messages.ja;
  const none = render(createElement(CalibrationScreen, { services: { loadSession: async () => ({ state: 'denied' }) }, t }));
  assert.equal(none, '');
  const loading = render(createElement(CalibrationScreen, { services: { loadSession: async () => ({ state: 'denied' }),
    loadSceneCalibration: async () => [] }, t }));
  for (const text of [t.calibrationTitle, t.calibrationNote, t.calibrationMemoryNote, t.checking]) {
    assert.ok(loading.includes(text), text);
  }
});
