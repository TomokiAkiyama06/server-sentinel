import test from 'node:test';
import assert from 'node:assert/strict';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { compile } from './compile.mjs';

await compile('src/i18n.ts', 'build/i18n.mjs');
await compile('src/shared/services.ts', 'build/services.mjs');
await compile('src/dashboard/live_loop.ts', 'build/live_loop.mjs');
await compile('src/dashboard/live.tsx', 'build/live.mjs');
const { messages } = await import('../build/i18n.mjs');
const { createDashboardServices, parseLiveSources, parseSession, MAX_FRAME_BYTES } = await import('../build/services.mjs');
const live = await import('../build/live_loop.mjs');
const { ApiError } = live;
const { LiveScreen } = await import('../build/live.mjs');

// Synthetic only: generated identifiers, no deployment or person value.
const origin = 'https://server-sentinel.test';
const csrf = 'A'.repeat(42) + 'b';
const source = '00000000-0000-4000-8000-00000000a001';
const sessionId = '00000000-0000-4000-8000-00000000b001';
const ownerBody = { csrf, role: 'owner', permissions: ['live:view', 'recordings:view'] };
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
const jpeg = (sequence, bytes = 16) => new Response(new Uint8Array(bytes), {
  status: 200, headers: { 'Content-Type': 'image/jpeg', 'X-Frame-Sequence': String(sequence) },
});
const signal = () => new AbortController().signal;

/** A fake fetch answering by "METHOD path" and recording every call. */
function fake(routes) {
  const calls = [];
  const request = async (url, init) => {
    const parsed = new URL(url);
    const key = `${init.method} ${parsed.pathname}`;
    calls.push({ key, url: parsed, init });
    const answer = routes[key];
    if (!answer) return new Response('synthetic private detail', { status: 404 });
    return typeof answer === 'function' ? answer(parsed, init) : answer.clone();
  };
  return { calls, request };
}

async function signedIn(routes = {}) {
  const transport = fake({ 'GET /api/session': json(ownerBody), ...routes });
  const services = createDashboardServices(origin, transport.request);
  assert.deepEqual(await services.loadSession(signal()), { state: 'allowed', role: 'owner', permissions: ['live:view', 'recordings:view'] });
  return { services, calls: transport.calls };
}

test('session: role and permissions map strictly; anything unknown fails closed', () => {
  assert.deepEqual(parseSession({ csrf, role: 'invited_user', permissions: ['live:view'] }),
    { session: { state: 'allowed', role: 'viewer', permissions: ['live:view'] }, csrf });
  assert.deepEqual(parseSession({ csrf, role: 'invited_user', permissions: [] }).session.permissions, []);
  for (const body of [null, [], {}, { ...ownerBody, role: 'viewer' }, { ...ownerBody, role: 'admin' },
    { ...ownerBody, permissions: ['live:view', 'admin'] }, { ...ownerBody, permissions: ['live:view', 'live:view'] },
    { ...ownerBody, permissions: 'live:view' }, { ...ownerBody, csrf: 'short' }, { ...ownerBody, csrf: `${csrf}=` }]) {
    assert.throws(() => parseSession(body), { code: 'invalid_response' });
  }
});

test('session: the generic refusal is a denied session, other failures are errors', async () => {
  for (const status of [401, 403, 404]) {
    const { request } = fake({ 'GET /api/session': new Response('', { status }) });
    assert.deepEqual(await createDashboardServices(origin, request).loadSession(signal()), { state: 'denied' });
  }
  const { request } = fake({ 'GET /api/session': new Response('synthetic private detail', { status: 503 }) });
  await assert.rejects(createDashboardServices(origin, request).loadSession(signal()), { code: 'unavailable' });
  const broken = fake({ 'GET /api/session': new Response('{}', { headers: { 'Content-Type': 'text/html' } }) });
  await assert.rejects(createDashboardServices(origin, broken.request).loadSession(signal()), { code: 'invalid_response' });
});

test('session read is a same-origin, uncached, redirect-refusing GET without a token', async () => {
  const { calls } = await signedIn();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url.href, `${origin}/api/session`);
  const { signal: passed, ...init } = calls[0].init;
  assert.ok(passed instanceof AbortSignal);
  assert.deepEqual(init, { method: 'GET', credentials: 'same-origin', mode: 'same-origin', cache: 'no-store',
    redirect: 'error', referrerPolicy: 'no-referrer', headers: { Accept: 'application/json' } });
});

test('sign-out sends the session CSRF token with an exact-Origin POST and no body', async () => {
  const { services, calls } = await signedIn({ 'POST /api/auth/sign-out': new Response(null, { status: 204 }) });
  await services.signOut(signal());
  const call = calls.at(-1);
  assert.equal(call.key, 'POST /api/auth/sign-out');
  assert.equal(call.init.body, undefined);
  assert.equal(call.init.referrer, '');
  assert.equal(call.init.referrerPolicy, 'same-origin');
  assert.equal(call.init.redirect, 'error');
  assert.deepEqual(call.init.headers, { Accept: 'application/json', 'X-CSRF-Token': csrf });
  // The token is gone after a sign-out: a later write cannot send a stale one.
  await assert.rejects(services.signOut(signal()), { code: 'unauthorized' });
  assert.equal(calls.length, 2);
});

test('no write is sent before a session supplied a token, and a refused sign-out is an error', async () => {
  const empty = fake({});
  const services = createDashboardServices(origin, empty.request);
  await assert.rejects(services.signOut(signal()), { code: 'unauthorized' });
  await assert.rejects(services.openLiveSession(source, signal()), { code: 'unauthorized' });
  services.closeLiveSession(sessionId);
  assert.equal(empty.calls.length, 0);
  const refused = await signedIn({ 'POST /api/auth/sign-out': new Response('', { status: 404 }) });
  await assert.rejects(refused.services.signOut(signal()), { code: 'unauthorized' });
});

test('live sources decode strictly and drop every other field', async () => {
  assert.deepEqual(parseLiveSources({ sources: [
    { id: source, name: '生成カメラ 1', health: 'online', serial: 'synthetic', device_path: '/dev/video0' },
    { id: '00000000-0000-4000-8000-00000000a002', name: 'generated 2' },
  ] }), [{ id: source, name: '生成カメラ 1', health: 'online' }, { id: '00000000-0000-4000-8000-00000000a002', name: 'generated 2', health: null }]);
  for (const body of [[], {}, { sources: {} }, { sources: [{ id: 'not-a-uuid', name: 'x' }] },
    { sources: [{ id: source.toUpperCase(), name: 'x' }] }, { sources: [{ id: source, name: '' }] },
    { sources: [{ id: source, name: 'x'.repeat(201) }] }, { sources: [{ id: source, name: 'x', health: 'healthy' }] },
    { sources: [{ id: source, name: 'a' }, { id: source, name: 'b' }] }]) {
    assert.throws(() => parseLiveSources(body), { code: 'invalid_response' });
  }
  const { services } = await signedIn({ 'GET /api/live/sources': json({ sources: [{ id: source, name: 'g', health: 'degraded' }] }) });
  assert.deepEqual(await services.loadLiveSources(signal()), [{ id: source, name: 'g', health: 'degraded' }]);
  const refused = await signedIn();
  await assert.rejects(refused.services.loadLiveSources(signal()), { code: 'unauthorized' });
});

test('opening a viewer session posts only the source id with the CSRF token', async () => {
  const { services, calls } = await signedIn({ 'POST /api/live/sessions': json({ session_id: sessionId, source_id: source }) });
  assert.equal(await services.openLiveSession(source, signal()), sessionId);
  const call = calls.at(-1);
  assert.equal(call.init.body, JSON.stringify({ source_id: source }));
  assert.deepEqual(call.init.headers, { Accept: 'application/json', 'X-CSRF-Token': csrf, 'Content-Type': 'application/json' });
  assert.equal(call.init.referrerPolicy, 'same-origin');
  await assert.rejects(services.openLiveSession('../admin', signal()), { code: 'invalid_request' });
  assert.equal(calls.length, 2);
  for (const body of [{}, { session_id: 'x' }, { session_id: sessionId.toUpperCase() }]) {
    const other = await signedIn({ 'POST /api/live/sessions': json(body) });
    await assert.rejects(other.services.openLiveSession(source, signal()), { code: 'invalid_response' });
  }
  const refused = await signedIn();
  await assert.rejects(refused.services.openLiveSession(source, signal()), { code: 'unauthorized' });
});

test('a frame is a fresh JPEG with a larger X-Frame-Sequence; 204 means none yet', async () => {
  const path = `GET /api/live/sessions/${sessionId}/frame`;
  const ok = await signedIn({ [path]: jpeg(7) });
  const frame = await ok.services.readLiveFrame(sessionId, 3, signal());
  assert.equal(frame.sequence, 7);
  assert.equal(frame.data.size, 16);
  const call = ok.calls.at(-1);
  assert.equal(call.url.search, '?after=3');
  assert.deepEqual(call.init.headers, { Accept: 'image/jpeg' });
  assert.equal(call.init.referrerPolicy, 'no-referrer');
  const none = await signedIn({ [path]: new Response(null, { status: 204 }) });
  assert.equal(await none.services.readLiveFrame(sessionId, 3, signal()), null);
  const invalid = [
    jpeg(3), jpeg(2), new Response(new Uint8Array(4), { headers: { 'Content-Type': 'image/png', 'X-Frame-Sequence': '9' } }),
    new Response(new Uint8Array(4), { headers: { 'Content-Type': 'image/jpeg' } }),
    new Response(new Uint8Array(4), { headers: { 'Content-Type': 'image/jpeg', 'X-Frame-Sequence': '09' } }),
    new Response(new Uint8Array(4), { headers: { 'Content-Type': 'image/jpeg', 'X-Frame-Sequence': '1e3' } }),
    new Response(new Uint8Array(4), { headers: { 'Content-Type': 'image/jpeg', 'X-Frame-Sequence': '99999999999999999' } }),
    new Response(new Uint8Array(0), { headers: { 'Content-Type': 'image/jpeg', 'X-Frame-Sequence': '9' } }),
    new Response(new Uint8Array(4), { headers: { 'Content-Type': 'image/jpeg', 'X-Frame-Sequence': '9', 'Content-Length': String(MAX_FRAME_BYTES + 1) } }),
    jpeg(9, MAX_FRAME_BYTES + 1),
  ];
  for (const response of invalid) {
    const other = await signedIn({ [path]: response });
    await assert.rejects(other.services.readLiveFrame(sessionId, 3, signal()), { code: 'invalid_response' });
  }
  const refused = await signedIn();
  await assert.rejects(refused.services.readLiveFrame(sessionId, 0, signal()), { code: 'unauthorized' });
  const failing = await signedIn({ [path]: new Response('', { status: 503 }) });
  await assert.rejects(failing.services.readLiveFrame(sessionId, 0, signal()), { code: 'unavailable' });
  for (const [id, after] of [['../../admin', 0], [sessionId, -1], [sessionId, 1.5]]) {
    await assert.rejects(ok.services.readLiveFrame(id, after, signal()), { code: 'invalid_request' });
  }
});

test('closing a viewer session is a keepalive POST with the CSRF token', async () => {
  const { services, calls } = await signedIn({ [`POST /api/live/sessions/${sessionId}/close`]: new Response(null, { status: 204 }) });
  services.closeLiveSession(sessionId);
  services.closeLiveSession('not-a-session');
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(calls.length, 2);
  const call = calls.at(-1);
  assert.equal(call.init.keepalive, true);
  assert.equal(call.init.signal, undefined);
  assert.deepEqual(call.init.headers, { Accept: 'application/json', 'X-CSRF-Token': csrf });
});

// -- the frame-pull loop, on a manual clock -----------------------------

function manualClock() {
  let now = 0;
  let id = 0;
  const timers = new Map();
  return {
    now: () => now,
    set(run, ms) { timers.set(++id, { at: now + ms, run }); return id; },
    clear(handle) { timers.delete(handle); },
    pending: () => timers.size,
    async advance(ms) {
      const end = now + ms;
      for (;;) {
        await flush();
        const due = [...timers.entries()].filter(([, timer]) => timer.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
        if (!due) break;
        timers.delete(due[0]);
        now = due[1].at;
        due[1].run();
      }
      now = end;
      await flush();
    },
  };
}
const flush = async () => { for (let index = 0; index < 20; index++) await Promise.resolve(); };
function visibility() {
  let hidden = false;
  const listeners = new Set();
  return {
    hidden: () => hidden,
    subscribe(changed) { listeners.add(changed); return () => listeners.delete(changed); },
    set(value) { hidden = value; for (const listener of [...listeners]) listener(); },
    listeners,
  };
}
/** A scripted transport: `reads` answers successive reads (a value or a function). */
function transport({ reads = [], open } = {}) {
  const log = [];
  let count = 0;
  let opened = 0;
  return {
    log,
    open: async (id, abort) => {
      log.push(['open', id]);
      if (open) return open(abort);
      return `00000000-0000-4000-8000-0000000c000${++opened}`;
    },
    read: async (id, after) => {
      log.push(['read', id, after]);
      const next = reads[Math.min(count++, reads.length - 1)];
      if (typeof next === 'function') return next();
      return next ?? null;
    },
    close: id => { log.push(['close', id]); },
  };
}
const frame = sequence => ({ sequence, data: new Blob([new Uint8Array(1)]) });
const refusal = () => { throw new ApiError('unauthorized'); };
const outage = () => { throw new ApiError('unavailable'); };

function run(options) {
  const clock = manualClock();
  const view = visibility();
  const statuses = [];
  const frames = [];
  const stop = live.startLiveLoop({ sourceId: source, visibility: view, clock,
    onFrame: value => { frames.push(value.sequence); }, onStatus: value => statuses.push(value), ...options });
  return { clock, view, statuses, frames, stop };
}

test('loop pulls newer frames at most every FRAME_INTERVAL_MS and reports live', async () => {
  const fakeTransport = transport({ reads: [frame(1), frame(2), null] });
  const loop = run({ transport: fakeTransport });
  await loop.clock.advance(0);
  assert.deepEqual(loop.frames, [1]);
  assert.deepEqual(loop.statuses, ['connecting', 'live']);
  await loop.clock.advance(live.FRAME_INTERVAL_MS - 1);
  assert.deepEqual(loop.frames, [1]);
  await loop.clock.advance(1);
  assert.deepEqual(loop.frames, [1, 2]);
  const reads = fakeTransport.log.filter(entry => entry[0] === 'read').map(entry => entry[2]);
  assert.deepEqual(reads, [0, 1]);
  loop.stop();
  assert.deepEqual(fakeTransport.log.at(-1), ['close', '00000000-0000-4000-8000-0000000c0001']);
  assert.equal(loop.clock.pending(), 0);
  assert.equal(loop.view.listeners.size, 0);
});

test('no newer frame for STALE_AFTER_MS marks the picture not current', async () => {
  const loop = run({ transport: transport({ reads: [frame(1), null] }) });
  await loop.clock.advance(live.STALE_AFTER_MS - 1);
  assert.equal(loop.statuses.at(-1), 'live');
  await loop.clock.advance(live.FRAME_INTERVAL_MS);
  assert.equal(loop.statuses.at(-1), 'stale');
  loop.stop();
});

test('transient failures back off exponentially, capped, and recover', async () => {
  assert.deepEqual([1, 2, 3, 4, 5, 6, 7].map(live.backoff), [500, 1000, 2000, 4000, 8000, 8000, 8000]);
  const fakeTransport = transport({ reads: [frame(1), outage, outage, outage, frame(2), null] });
  const loop = run({ transport: fakeTransport });
  await loop.clock.advance(0);
  await loop.clock.advance(live.FRAME_INTERVAL_MS);
  assert.equal(loop.statuses.at(-1), 'retrying');
  const readsAt = () => fakeTransport.log.filter(entry => entry[0] === 'read').length;
  assert.equal(readsAt(), 2);
  await loop.clock.advance(499);
  assert.equal(readsAt(), 2);
  await loop.clock.advance(1);
  assert.equal(readsAt(), 3);
  await loop.clock.advance(1000);
  assert.equal(readsAt(), 4);
  await loop.clock.advance(2000);
  assert.deepEqual(loop.frames, [1, 2]);
  assert.equal(loop.statuses.at(-1), 'live');
  // The session was kept: no close and no second open while retrying.
  assert.equal(fakeTransport.log.filter(entry => entry[0] !== 'read').length, 1);
  loop.stop();
});

test('a refusal ends the loop for good: session closed, frame dropped, nothing retried', async () => {
  for (const at of ['read', 'open']) {
    const fakeTransport = at === 'read' ? transport({ reads: [frame(1), refusal] })
      : transport({ open: () => { throw new ApiError('unauthorized'); } });
    const loop = run({ transport: fakeTransport });
    await loop.clock.advance(live.FRAME_INTERVAL_MS);
    assert.equal(loop.statuses.at(-1), 'ended');
    const before = fakeTransport.log.length;
    await loop.clock.advance(60_000);
    loop.view.set(true);
    loop.view.set(false);
    await loop.clock.advance(60_000);
    assert.equal(fakeTransport.log.length, before);
    assert.equal(loop.clock.pending(), 0);
    if (at === 'read') assert.deepEqual(fakeTransport.log.at(-1), ['close', '00000000-0000-4000-8000-0000000c0001']);
    loop.stop();
    assert.equal(fakeTransport.log.length, before);
  }
});

test('a transient open failure retries with backoff; a hidden page pauses and reopens', async () => {
  let attempts = 0;
  const fakeTransport = transport({ reads: [frame(1), null], open: () => {
    attempts += 1;
    if (attempts === 1) throw new ApiError('unavailable');
    return `00000000-0000-4000-8000-0000000d000${attempts}`;
  } });
  const loop = run({ transport: fakeTransport });
  await loop.clock.advance(0);
  assert.equal(loop.statuses.at(-1), 'retrying');
  await loop.clock.advance(live.backoff(1));
  assert.equal(loop.statuses.at(-1), 'live');
  loop.view.set(true);
  assert.equal(loop.statuses.at(-1), 'paused');
  assert.deepEqual(fakeTransport.log.at(-1), ['close', '00000000-0000-4000-8000-0000000d0002']);
  const paused = fakeTransport.log.length;
  await loop.clock.advance(60_000);
  assert.equal(fakeTransport.log.length, paused, 'nothing is requested while hidden');
  loop.view.set(false);
  await loop.clock.advance(0);
  assert.deepEqual(fakeTransport.log.slice(paused, paused + 2), [['open', source], ['read', '00000000-0000-4000-8000-0000000d0003', 0]]);
  loop.stop();
});

test('a session granted after the loop stopped is closed at once', async () => {
  let grant;
  const fakeTransport = transport({ open: () => new Promise(resolve => { grant = resolve; }) });
  const loop = run({ transport: fakeTransport });
  await loop.clock.advance(0);
  loop.stop();
  grant('00000000-0000-4000-8000-0000000e0001');
  await loop.clock.advance(1000);
  assert.deepEqual(fakeTransport.log, [['open', source], ['close', '00000000-0000-4000-8000-0000000e0001']]);
});

test('a page hidden at start never opens a session', async () => {
  const fakeTransport = transport();
  const clock = manualClock();
  const view = visibility();
  view.set(true);
  const statuses = [];
  const stop = live.startLiveLoop({ transport: fakeTransport, sourceId: source, visibility: view, clock,
    onFrame: () => undefined, onStatus: value => statuses.push(value) });
  await clock.advance(10_000);
  assert.deepEqual(statuses, ['paused']);
  assert.deepEqual(fakeTransport.log, []);
  stop();
});

// -- screen markup --------------------------------------------------------

test('live screen offers no download, export, link or media element and stays neutral', () => {
  const services = { loadSession: async () => ({ state: 'denied' }), loadLiveSources: async () => [],
    openLiveSession: async () => sessionId, readLiveFrame: async () => null, closeLiveSession: () => undefined };
  for (const locale of ['ja', 'en']) {
    const html = renderToStaticMarkup(createElement(LiveScreen, { services, t: messages[locale] }));
    assert.doesNotMatch(html, /<a\b|download|<video|<img|<iframe|<source/i);
    const placeholder = renderToStaticMarkup(createElement(LiveScreen, { services: { loadSession: services.loadSession }, t: messages[locale] }));
    assert.match(placeholder, new RegExp(messages[locale].foundation));
  }
  for (const locale of ['ja', 'en']) {
    const copy = Object.entries(messages[locale]).filter(([key]) => key.startsWith('live')).map(([, value]) => value).join('\n');
    assert.doesNotMatch(copy, /犯人|侵入者|不審者|加害|culprit|attacker|intruder|suspect/i);
    assert.match(messages[locale].liveViewOnly, locale === 'ja' ? /防ぐものではありません/ : /does not prevent/);
  }
});

test('sign-out first closes every viewer session this page still holds', async () => {
  const close = `POST /api/live/sessions/${sessionId}/close`;
  const { services, calls } = await signedIn({
    'POST /api/live/sessions': json({ session_id: sessionId }),
    [close]: new Response(null, { status: 204 }),
    'POST /api/auth/sign-out': new Response(null, { status: 204 }),
  });
  await services.openLiveSession(source, signal());
  await services.signOut(signal());
  assert.deepEqual(calls.slice(-2).map(call => call.key), [close, 'POST /api/auth/sign-out']);
  assert.deepEqual(calls.at(-2).init.headers, { Accept: 'application/json', 'X-CSRF-Token': csrf });
  // A close already sent is not repeated, and a later close sends nothing.
  services.closeLiveSession(sessionId);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(calls.filter(call => call.key === close).length, 1);
  const again = await signedIn({
    'POST /api/live/sessions': json({ session_id: sessionId }),
    [close]: new Response(null, { status: 204 }),
    'POST /api/auth/sign-out': new Response(null, { status: 204 }),
  });
  await again.services.openLiveSession(source, signal());
  again.services.closeLiveSession(sessionId);
  await again.services.signOut(signal());
  assert.equal(again.calls.filter(call => call.key === close).length, 1);
});

test('a hung close or open never holds the sign-out; an open granted meanwhile is closed first', async () => {
  const close = `POST /api/live/sessions/${sessionId}/close`;
  // A close that never answers: sign-out still goes out after the bound.
  const hung = fake({ 'GET /api/session': json(ownerBody), 'POST /api/live/sessions': json({ session_id: sessionId }),
    [close]: () => new Promise(() => {}), 'POST /api/auth/sign-out': new Response(null, { status: 204 }) });
  const services = createDashboardServices(origin, hung.request, { cleanupMs: 20 });
  await services.loadSession(signal());
  await services.openLiveSession(source, signal());
  await services.signOut(signal());
  assert.deepEqual(hung.calls.slice(-2).map(call => call.key), [close, 'POST /api/auth/sign-out']);
  // An open in flight when sign-out starts: its grant is closed before the
  // sign-out request, and no new open starts meanwhile.
  let grant;
  const racing = fake({ 'GET /api/session': json(ownerBody),
    'POST /api/live/sessions': () => new Promise(resolve => { grant = resolve; }),
    [close]: new Response(null, { status: 204 }), 'POST /api/auth/sign-out': new Response(null, { status: 204 }) });
  const other = createDashboardServices(origin, racing.request, { cleanupMs: 1000 });
  await other.loadSession(signal());
  const opened = other.openLiveSession(source, signal());
  await flush();
  const signingOut = other.signOut(signal());
  await assert.rejects(other.openLiveSession(source, signal()), { code: 'unauthorized' });
  grant(json({ session_id: sessionId }));
  await signingOut;
  assert.equal(await opened, sessionId);
  assert.deepEqual(racing.calls.map(call => call.key), ['GET /api/session', 'POST /api/live/sessions', close, 'POST /api/auth/sign-out']);
});

test('a stalled frame request is abandoned: the picture is never left labelled live', async () => {
  let aborted = null;
  let reads = 0;
  const stalled = transport();
  stalled.read = async (id, after, abort) => {
    reads += 1;
    if (reads === 1) return frame(1);
    aborted = abort;
    return new Promise(() => {});
  };
  const loop = run({ transport: stalled });
  await loop.clock.advance(live.FRAME_INTERVAL_MS);
  assert.equal(loop.statuses.at(-1), 'live');
  await loop.clock.advance(live.REQUEST_TIMEOUT_MS - 1);
  assert.equal(loop.statuses.at(-1), 'live');
  await loop.clock.advance(1);
  assert.equal(loop.statuses.at(-1), 'retrying');
  assert.equal(aborted.aborted, true);
  assert.ok(live.REQUEST_TIMEOUT_MS < live.STALE_AFTER_MS);
  // A stalled open is bounded the same way.
  const hungOpen = transport({ open: () => new Promise(() => {}) });
  const second = run({ transport: hungOpen });
  await second.clock.advance(live.REQUEST_TIMEOUT_MS);
  assert.equal(second.statuses.at(-1), 'retrying');
  loop.stop();
  second.stop();
});

test('a frame decoded after a pause is reported as no longer current', async () => {
  let release;
  const checks = [];
  const fakeTransport = transport({ reads: [frame(1), null] });
  const clock = manualClock();
  const view = visibility();
  const stop = live.startLiveLoop({ transport: fakeTransport, sourceId: source, visibility: view, clock,
    onStatus: () => undefined,
    onFrame: (_, current) => new Promise(resolve => { release = () => { checks.push(current()); resolve(); }; }) });
  await clock.advance(0);
  view.set(true);
  release();
  await clock.advance(0);
  assert.deepEqual(checks, [false]);
  stop();
});

test('a stalled decode shares the request deadline and is then no longer current', async () => {
  const checks = [];
  let finish;
  let calls = 0;
  const fakeTransport = transport({ reads: [frame(1), frame(2)] });
  const clock = manualClock();
  const view = visibility();
  const statuses = [];
  const stop = live.startLiveLoop({ transport: fakeTransport, sourceId: source, visibility: view, clock,
    onStatus: value => statuses.push(value),
    onFrame: (_, current) => {
      calls += 1;
      if (calls === 1) return undefined;
      return new Promise(resolve => { finish = () => { checks.push(current()); resolve(); }; });
    } });
  await clock.advance(live.FRAME_INTERVAL_MS);
  assert.equal(statuses.at(-1), 'live');
  await clock.advance(live.REQUEST_TIMEOUT_MS);
  assert.equal(statuses.at(-1), 'retrying');
  finish();
  await clock.advance(0);
  assert.deepEqual(checks, [false]);
  stop();
});

test('a session granted after the open timed out is closed at once', async () => {
  let grant;
  const fakeTransport = transport({ open: () => new Promise(resolve => { grant = resolve; }) });
  const loop = run({ transport: fakeTransport });
  await loop.clock.advance(live.REQUEST_TIMEOUT_MS);
  assert.equal(loop.statuses.at(-1), 'retrying');
  grant('00000000-0000-4000-8000-0000000f0001');
  await loop.clock.advance(0);
  assert.deepEqual(fakeTransport.log.filter(entry => entry[0] === 'close'), [['close', '00000000-0000-4000-8000-0000000f0001']]);
  loop.stop();
});

test('a stalled sign-out request is abandoned and reported, and can be retried', async () => {
  let answer = () => new Promise(() => {});
  const stalled = fake({ 'GET /api/session': json(ownerBody), 'POST /api/auth/sign-out': (url, init) => answer(url, init) });
  const services = createDashboardServices(origin, stalled.request, { cleanupMs: 10, signOutMs: 30 });
  await services.loadSession(signal());
  await assert.rejects(services.signOut(signal()), { code: 'unavailable' });
  answer = () => new Response(null, { status: 204 });
  await services.signOut(signal());
  assert.equal(stalled.calls.filter(call => call.key === 'POST /api/auth/sign-out').length, 2);
});

test('the picture turns stale STALE_AFTER_MS after the last frame even while a pull is pending', async () => {
  const clock = manualClock();
  const view = visibility();
  const statuses = [];
  let reads = 0;
  const slow = transport();
  // Every pull after the first answers 204 just before the request deadline.
  slow.read = () => {
    reads += 1;
    if (reads === 1) return Promise.resolve(frame(1));
    return new Promise(resolve => { clock.set(() => resolve(null), live.REQUEST_TIMEOUT_MS - 100); });
  };
  const stop = live.startLiveLoop({ transport: slow, sourceId: source, visibility: view, clock,
    onFrame: () => undefined, onStatus: value => statuses.push(value) });
  await clock.advance(0);
  assert.equal(statuses.at(-1), 'live');
  await clock.advance(live.STALE_AFTER_MS - 1);
  assert.equal(statuses.at(-1), 'live');
  await clock.advance(1);
  assert.equal(statuses.at(-1), 'stale');
  assert.equal(reads, 3, 'the third pull is still pending when the picture turns stale');
  stop();
  // Only the fake read's own answer timer may remain.
  assert.equal(clock.pending(), 1);
});
