import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { compile } from './compile.mjs';

await compile('src/api.ts', 'build/api.mjs');
await compile('src/domain.ts', 'build/domain.mjs');
await compile('src/i18n.ts', 'build/i18n.mjs');
await compile('src/shared/mutations.ts', 'build/mutations.mjs');
const { createApiClient, ApiError } = await import('../build/api.mjs');
const { canVisit, deniedServices, views } = await import('../build/domain.mjs');
const { messages } = await import('../build/i18n.mjs');
const { MutationQueue } = await import('../build/mutations.mjs');
const origin = 'https://server-sentinel.test';
const decode = value => {
  if (typeof value !== 'object' || value === null || !Array.isArray(value.items)) throw new Error('private response');
  return value.items;
};

test('default session denies access to all nine sections without a provider', async () => {
  const session = await deniedServices.loadSession(new AbortController().signal);
  assert.deepEqual(session, { state: 'denied' });
  assert.equal(views.length, 9);
  for (const view of views) assert.equal(canVisit(session, view), false);
});

test('view permissions remain independent; viewer never gains owner metadata', () => {
  for (const permissions of [[], ['live:view'], ['recordings:view'], ['live:view', 'recordings:view']]) {
    const session = { state: 'allowed', role: 'viewer', permissions };
    assert.equal(canVisit(session, 'live'), permissions.includes('live:view'));
    assert.equal(canVisit(session, 'recordings'), permissions.includes('recordings:view'));
    assert.equal(canVisit(session, 'timeline'), permissions.includes('recordings:view'));
    for (const view of ['sources', 'nodes', 'presence', 'access', 'storage']) assert.equal(canVisit(session, view), false);
  }
});

test('both localization dictionaries have identical keys', () => {
  assert.deepEqual(Object.keys(messages.ja).sort(), Object.keys(messages.en).sort());
});

test('client requests only same-origin API JSON without caching or following redirects', async () => {
  const controller = new AbortController();
  let calls = 0;
  const api = createApiClient(origin, async (url, options) => {
    calls++;
    assert.equal(url, `${origin}/api/example?limit=4`);
    assert.deepEqual(options, {
      method: 'GET', credentials: 'same-origin', mode: 'same-origin', cache: 'no-store',
      redirect: 'error', referrerPolicy: 'no-referrer', headers: { Accept: 'application/json' }, signal: controller.signal,
    });
    return Response.json({ items: ['synthetic-source-1'] });
  });
  assert.deepEqual(await api.read('/api/example?limit=4', decode, controller.signal), ['synthetic-source-1']);
  assert.equal(calls, 1);
});

test('external, scheme-relative and escaped paths cannot invoke fetch', async () => {
  const api = createApiClient(origin, () => { assert.fail('fetch must not run'); });
  for (const path of ['https://outside.invalid/api/x', '//outside.invalid/api/x', '/api/../outside', '/api/%2e%2e/outside', '/api/\\outside', '/api/x#fragment', '/assets/app.js']) {
    await assert.rejects(api.read(path, decode), error => error instanceof ApiError && error.code === 'invalid_request');
  }
});

test('HTTP and network failures never expose response content', async () => {
  for (const [status, code] of [[401, 'unauthorized'], [403, 'unauthorized'], [500, 'unavailable']]) {
    const api = createApiClient(origin, async () => new Response('private server error detail', { status }));
    await assert.rejects(api.read('/api/example', decode), error => {
      assert.equal(error.message, code);
      assert.equal(error.cause, undefined);
      return error.code === code;
    });
  }
  const api = createApiClient(origin, async () => { throw new Error('private transport detail'); });
  await assert.rejects(api.read('/api/example', decode), { code: 'unavailable' });
});

test('invalid content, schema and JSON fail closed; abort stays local', async () => {
  for (const response of [new Response('html'), Response.json({ wrong: true }), new Response('{', { headers: { 'Content-Type': 'application/json' } })]) {
    await assert.rejects(createApiClient(origin, async () => response).read('/api/example', decode), { code: 'invalid_response' });
  }
  const controller = new AbortController();
  controller.abort();
  const api = createApiClient(origin, async () => { throw new Error(); });
  await assert.rejects(api.read('/api/example', decode, controller.signal), { code: 'cancelled' });
});

test('production assets contain no test provider or runtime remote imports', async () => {
  const html = await readFile('dist/index.html', 'utf8');
  const bundle = await readFile('dist/assets/app.js', 'utf8');
  assert.match(html, /lang="ja"/);
  assert.match(html, /connect-src 'self'/);
  assert.doesNotMatch(html, /https?:\/\//);
  assert.doesNotMatch(bundle, /\/api\/mock|synthetic-source|tests\/harness|import\s*\(\s*['"]https?:/);
  for (const name of ['react', 'react-dom', 'scheduler']) assert.match(await readFile(`dist/${name}-LICENSE.txt`, 'utf8'), /MIT License/);
});

test('a repeated mutation on the same recording is refused while one is in flight', async () => {
  const queue = new MutationQueue();
  const runs = [];
  let release;
  const blocked = new Promise(resolve => { release = resolve; });
  const outcomes = [];
  assert.equal(queue.start('recording-a', signal => { runs.push(['a', signal]); return blocked; }, outcome => outcomes.push(outcome)), true);
  assert.equal(queue.start('recording-a', () => { assert.fail('second write must not run'); }, () => assert.fail('no settle')), false);
  assert.equal(queue.has('recording-a'), true);
  assert.deepEqual(queue.pending, ['recording-a']);
  // A different recording is independent and not blocked by the first.
  assert.equal(queue.start('recording-b', () => Promise.resolve(), outcome => outcomes.push(outcome)), true);
  assert.deepEqual(queue.pending, ['recording-a', 'recording-b']);
  release();
  await blocked;
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(outcomes.sort(), ['done', 'done']);
  assert.deepEqual(queue.pending, []);
  assert.equal(runs.length, 1);
  // Once settled the same recording can be mutated again.
  assert.equal(queue.start('recording-a', () => Promise.resolve(), () => {}), true);
});

test('aborting a replaced session cancels mutations without reporting failure', async () => {
  const queue = new MutationQueue();
  const outcomes = [];
  let release;
  const blocked = new Promise(resolve => { release = resolve; });
  let observed;
  queue.start('recording-a', signal => { observed = signal; return blocked; }, outcome => outcomes.push(outcome));
  assert.equal(observed.aborted, false);
  queue.abortAll();
  assert.equal(observed.aborted, true);
  assert.deepEqual(queue.pending, []);
  release();
  await blocked;
  await new Promise(resolve => setImmediate(resolve));
  // Aborted work is neither a fresh result nor an error banner.
  assert.deepEqual(outcomes, ['aborted']);
});

test('a rejected mutation settles as failed and frees the recording', async () => {
  const queue = new MutationQueue();
  const outcomes = [];
  queue.start('recording-a', () => Promise.reject(new Error('synthetic private detail')), outcome => outcomes.push(outcome));
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(outcomes, ['failed']);
  assert.deepEqual(queue.pending, []);
  assert.equal(queue.start('recording-a', () => Promise.resolve(), () => {}), true);
});
