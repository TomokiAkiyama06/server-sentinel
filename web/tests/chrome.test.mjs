import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describeException, launchChrome, pageFor } from './chrome.mjs';

// Synthetic stand-ins for Chrome's --remote-debugging-pipe transport (#197).
// Each launch appends its pid to a ledger so the tests can prove that hung
// processes are terminated rather than leaked.
async function fakeChrome(t, behaviour) {
  const directory = await mkdtemp(join(tmpdir(), 'server-sentinel-fake-chrome-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const ledger = join(directory, 'launches');
  const executable = join(directory, 'fake-chrome');
  await writeFile(executable, `#!${process.execPath}
const fs = require('node:fs');
fs.appendFileSync(${JSON.stringify(ledger)}, process.pid + '\\n');
const launch = fs.readFileSync(${JSON.stringify(ledger)}, 'utf8').trim().split('\\n').length;
const behaviour = ${JSON.stringify(behaviour)};
const mode = behaviour[Math.min(launch, behaviour.length) - 1];
process.stderr.write('synthetic chrome launch ' + launch + ' mode ' + mode + '\\n');
if (mode === 'exit') process.exit(3);
if (mode === 'stubborn') process.on('SIGTERM', () => {});
setInterval(() => {}, 1000);
let buffered = '';
let answered = 0;
fs.createReadStream(null, { fd: 3 }).on('data', data => {
  buffered += data;
  let end;
  while ((end = buffered.indexOf('\\0')) !== -1) {
    const message = JSON.parse(buffered.slice(0, end));
    buffered = buffered.slice(end + 1);
    if (mode === 'ready' || (mode === 'once' && answered++ === 0)) fs.writeSync(4, JSON.stringify({ id: message.id, result: { product: 'SyntheticChrome/1.0' } }) + '\\0');
  }
});
`);
  await chmod(executable, 0o755);
  const pids = async () => (await readFile(ledger, 'utf8').catch(() => '')).trim().split('\n').filter(Boolean).map(Number);
  return { executable, pids };
}

const alive = pid => { try { process.kill(pid, 0); return true; } catch { return false; } };
const fast = { readinessTimeoutMs: 400, terminateGraceMs: 200 };

test('a Chrome that never answers its first CDP command is replaced by a fresh launch', { timeout: 15000 }, async t => {
  const fake = await fakeChrome(t, ['hang', 'ready']);
  const logs = [];
  const browser = await launchChrome({ ...fast, executable: fake.executable, log: line => logs.push(line) });
  try {
    assert.equal(browser.version.product, 'SyntheticChrome/1.0');
    assert.deepEqual(await browser.command('Browser.getVersion'), { product: 'SyntheticChrome/1.0' });
  } finally { await browser.close(); }
  const pids = await fake.pids();
  assert.equal(pids.length, 2);
  for (const pid of pids) assert.equal(alive(pid), false, `fake Chrome ${pid} must be terminated`);
  assert.match(logs.join('\n'), /attempt 1\/3 failed the DevTools readiness probe: Chrome command timeout: Browser\.getVersion/);
  assert.match(logs.join('\n'), /readiness probe on launch attempt 2\/3/);
});

test('readiness retries are bounded and the failure carries every attempt\'s stderr', { timeout: 15000 }, async t => {
  const fake = await fakeChrome(t, ['hang', 'stubborn', 'exit']);
  const started = Date.now();
  await assert.rejects(
    launchChrome({ ...fast, executable: fake.executable, log: () => {} }),
    error => {
      assert.match(error.message, /did not become ready after 3 launch attempts/);
      assert.match(error.message, /attempt 1\/3: Chrome command timeout: Browser\.getVersion/);
      assert.match(error.message, /synthetic chrome launch 1 mode hang/);
      assert.match(error.message, /synthetic chrome launch 2 mode stubborn/);
      assert.match(error.message, /signal SIGKILL/, 'a Chrome ignoring SIGTERM is escalated to SIGKILL');
      assert.match(error.message, /attempt 3\/3: Chrome (exited before the command completed|DevTools pipe failed).*\[exit code 3, signal null\]/);
      assert.match(error.message, /synthetic chrome launch 3 mode exit/);
      return true;
    },
  );
  assert.ok(Date.now() - started < 10000);
  const pids = await fake.pids();
  assert.equal(pids.length, 3, 'no launch beyond the configured bound');
  for (const pid of pids) assert.equal(alive(pid), false, `fake Chrome ${pid} must be terminated`);
});

test('a missing browser executable fails immediately without retries', { timeout: 15000 }, async t => {
  const directory = await mkdtemp(join(tmpdir(), 'server-sentinel-no-chrome-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const logs = [];
  await assert.rejects(
    launchChrome({ ...fast, executable: join(directory, 'missing-chrome'), log: line => logs.push(line) }),
    /Chrome is unavailable; install\/provide a browser executable/,
  );
  assert.deepEqual(logs, []);
});

test('commands after readiness keep a plain timeout and are never retried', { timeout: 15000 }, async t => {
  const fake = await fakeChrome(t, ['once']);
  const browser = await launchChrome({ ...fast, executable: fake.executable, commandTimeoutMs: 300, log: () => {} });
  try {
    await assert.rejects(browser.command('Target.createBrowserContext'), /Chrome command timeout: Target\.createBrowserContext \(300 ms\)/);
  } finally { await browser.close(); }
  assert.equal((await fake.pids()).length, 1, 'a post-readiness failure must not relaunch Chrome');
});

// An in-process stand-in for a launched browser (#322): `pageFor` needs only
// `command` and `on`. `answer` decides each command's result; `emit` delivers
// a CDP event on the page's session.
function fakeBrowser(answer) {
  const listeners = new Map();
  const browser = {
    calls: [],
    async command(method, params) { browser.calls.push(method); return answer(method, params) ?? {}; },
    on(method, listener) {
      if (!listeners.has(method)) listeners.set(method, new Set());
      listeners.get(method).add(listener);
      return () => listeners.get(method).delete(listener);
    },
    emit(method, params) { for (const listener of listeners.get(method) ?? []) listener(params, 'session-1'); },
  };
  return browser;
}
const setup = method => ({
  'Target.createBrowserContext': { browserContextId: 'context-1' },
  'Target.createTarget': { targetId: 'target-1' },
  'Target.attachToTarget': { sessionId: 'session-1' },
})[method];
const viewport = { width: 390, height: 844 };
const thrown = description => ({ exceptionDetails: { exception: {
  type: 'object', subtype: 'error', className: description.split(':', 1)[0], description,
} } });

test('evaluation failures are described without page values', () => {
  const describe = description => describeException(thrown(description).exceptionDetails);
  // Allowlisted V8 shapes keep their message: the only variable part is an
  // identifier from the test's own expression.
  for (const message of [
    "TypeError: Cannot read properties of null (reading 'textContent')",
    "TypeError: Cannot set properties of undefined (setting 'value')",
    'TypeError: document.getElementById is not a function',
    'ReferenceError: missingName is not defined',
  ]) assert.equal(describe(`${message}\n    at <anonymous>:1:26`), message);
  // Any other message is reduced to its class, whatever it quotes.
  for (const [description, expected] of [
    ['SyntaxError: Unexpected token \'a\', "a private value" is not valid JSON', 'SyntaxError'],
    ['Error: refused 0123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WXYZ', 'Error'],
    ['Error: refused 0123-4567', 'Error'],
    ['TypeError: person-a@example.invalid has token abc_DEF-123', 'TypeError'],
    ["TypeError: Cannot read properties of null (reading '0123-4567')", 'TypeError'],
    ["TypeError: Cannot read properties of null (reading 'textContent') 0123-4567", 'TypeError'],
  ]) assert.equal(describe(description), expected);
  assert.equal(describeException({ exception: { type: 'object', subtype: 'error', className: 'Bad Class', description: 'x' } }), 'Error');
  assert.equal(describeException({ exception: { type: 'string', value: 'a private value' } }), 'non-Error value thrown (string)');
  assert.equal(describeException({ text: 'Uncaught' }), 'non-Error value thrown (unknown)');
});

test('wait keeps polling across a navigation but fails on an expression error', async () => {
  let evaluations = 0;
  const navigating = fakeBrowser(method => {
    if (method !== 'Runtime.evaluate') return setup(method);
    evaluations++;
    if (evaluations === 1) throw new Error('Execution context was destroyed.');
    return { result: { value: evaluations === 3 } };
  });
  await (await pageFor(navigating, viewport)).wait("location.pathname === '/app/'");
  assert.equal(evaluations, 3);

  const failing = fakeBrowser(method => (method === 'Runtime.evaluate'
    ? thrown("TypeError: Cannot read properties of null (reading 'textContent')") : setup(method)));
  await assert.rejects((await pageFor(failing, viewport)).wait("document.getElementById('m').textContent === 'x'"),
    { message: "Browser evaluation failed: TypeError: Cannot read properties of null (reading 'textContent')" });
  assert.equal(failing.calls.filter(method => method === 'Runtime.evaluate').length, 1, 'an expression error is not retried');

  // A poll that never leaves the navigation times out and names the refusal.
  const stuck = fakeBrowser(method => {
    if (method === 'Runtime.evaluate') throw new Error('Inspected target navigated or closed');
    return setup(method);
  });
  await assert.rejects((await pageFor(stuck, viewport)).wait('true'),
    { message: 'Browser DOM assertion timed out (last CDP refusal while navigating: Inspected target navigated or closed)' });
});

test('navigate resolves only once the new document has parsed', async () => {
  let release;
  const browser = fakeBrowser(method => {
    if (method !== 'Page.navigate') return setup(method);
    // The previous document finishes parsing while the navigation is pending;
    // that must not count for the new one.
    browser.emit('Page.frameNavigated', { frame: { id: 'frame-1', loaderId: 'loader-old' } });
    browser.emit('Page.domContentEventFired', { timestamp: 1 });
    release = () => {
      browser.emit('Page.frameNavigated', { frame: { id: 'child', parentId: 'frame-1', loaderId: 'loader-child' } });
      browser.emit('Page.frameNavigated', { frame: { id: 'frame-1', loaderId: 'loader-new' } });
      browser.emit('Page.domContentEventFired', { timestamp: 2 });
    };
    return { frameId: 'frame-1', loaderId: 'loader-new' };
  });
  const page = await pageFor(browser, viewport);
  let settled = false;
  const navigation = page.navigate('http://localhost/').then(() => { settled = true; });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(settled, false, 'the previous document does not satisfy the navigation');
  release();
  await navigation;

  // The new document may commit and parse before Page.navigate answers.
  const early = fakeBrowser(method => {
    if (method !== 'Page.navigate') return setup(method);
    early.emit('Page.frameNavigated', { frame: { id: 'frame-1', loaderId: 'loader-new' } });
    early.emit('Page.domContentEventFired', { timestamp: 1 });
    return { frameId: 'frame-1', loaderId: 'loader-new' };
  });
  await (await pageFor(early, viewport)).navigate('http://localhost/', 50);

  const refused = fakeBrowser(method => (method === 'Page.navigate'
    ? { frameId: 'frame-1', loaderId: 'l', errorText: 'net::ERR_BLOCKED_BY_CLIENT' } : setup(method)));
  await assert.rejects((await pageFor(refused, viewport)).navigate('http://localhost/'), /Navigation failed: net::ERR_BLOCKED_BY_CLIENT/);
  const silent = fakeBrowser(method => (method === 'Page.navigate' ? { frameId: 'frame-1', loaderId: 'l' } : setup(method)));
  await assert.rejects((await pageFor(silent, viewport)).navigate('http://localhost/', 50), /did not reach DOMContentLoaded within 50 ms/);
});
