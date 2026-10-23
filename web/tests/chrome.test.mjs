import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { clickWhenEnabled, CommandError, describeCommandError, describeException, isTeardownError, launchChrome, pageFor, routeTracker,
  unexpectedAbandoned } from './chrome.mjs';

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
    emit(method, params, session = 'session-1') { for (const listener of listeners.get(method) ?? []) listener(params, session); },
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

test('interception failures are described without request values', () => {
  const refused = (method, message, code = -32602) => describeCommandError(new CommandError(method, { code, message }));
  assert.equal(refused('Fetch.fulfillRequest', 'Invalid InterceptionId.'),
    'Fetch.fulfillRequest refused (CDP -32602): Invalid InterceptionId.');
  assert.equal(refused('Fetch.failRequest', 'Session with given id not found.', -32001),
    'Fetch.failRequest refused (CDP -32001): Session with given id not found.');
  // A protocol message outside the fixed set, a malformed method or code keep no value.
  assert.equal(refused('Fetch.fulfillRequest', 'Invalid header: 0123-4567-89AB'), 'Fetch.fulfillRequest refused (CDP -32602)');
  assert.equal(refused('person-a@example.invalid', 'Invalid InterceptionId.', 'x'), 'unknown method refused (CDP unknown): Invalid InterceptionId.');
  // This adapter's own errors carry only a method, a number or a process status.
  for (const message of ['Chrome command timeout: Fetch.fulfillRequest (10000 ms)', 'Chrome was closed.',
    'Chrome exited before the command completed (code null, signal SIGTERM).']) {
    assert.equal(describeCommandError(new Error(message)), message);
  }
  // Anything else (e.g. a handler bug quoting request data) is reduced to its class.
  assert.equal(describeCommandError(new TypeError('/api/mock/0123-4567 is not valid JSON')), 'TypeError raised by the interceptor');
  assert.equal(describeCommandError(new Error('Chrome command timeout: Fetch.fulfillRequest (10 ms) 0123')), 'Error raised by the interceptor');
  assert.equal(describeCommandError('a private value'), 'non-Error value raised by the interceptor');
});

test('answer tells a request the page cancelled apart from a genuine interception error', async () => {
  const invalid = new CommandError('Fetch.fulfillRequest', { code: -32602, message: 'Invalid InterceptionId.' });
  let refusal = invalid;
  const browser = fakeBrowser(method => {
    if (method !== 'Fetch.fulfillRequest') return setup(method);
    if (refusal) throw refusal;
    return {};
  });
  const page = await pageFor(browser, viewport);
  // Cancelled by the page (reported before the refusal, as Chrome does): abandoned.
  browser.emit('Network.loadingFailed', { requestId: 'network-1', canceled: true, errorText: 'net::ERR_ABORTED' });
  assert.equal(await page.answer('network-1', 'Fetch.fulfillRequest', { requestId: 'job-1' }), false);
  // The cancellation may also arrive shortly after the refusal.
  setTimeout(() => browser.emit('Network.loadingFailed', { requestId: 'network-2', canceled: true }), 30);
  assert.equal(await page.answer('network-2', 'Fetch.fulfillRequest', { requestId: 'job-2' }), false);
  // The same refusal without a page cancellation is a harness error.
  browser.emit('Network.loadingFailed', { requestId: 'network-3', canceled: false, errorText: 'net::ERR_FAILED' });
  await assert.rejects(page.answer('network-3', 'Fetch.fulfillRequest', { requestId: 'job-3' }, 100), error => error === invalid);
  await assert.rejects(page.answer(undefined, 'Fetch.fulfillRequest', { requestId: 'job-0' }, 100), error => error === invalid);
  // A cancellation on another page's session does not count.
  browser.emit('Network.loadingFailed', { requestId: 'network-4', canceled: true }, 'session-2');
  await assert.rejects(page.answer('network-4', 'Fetch.fulfillRequest', { requestId: 'job-4' }, 100), error => error === invalid);
  // Any other refusal or adapter failure is rethrown at once, cancelled or not.
  refusal = new CommandError('Fetch.fulfillRequest', { code: -32602, message: 'Invalid header' });
  await assert.rejects(page.answer('network-1', 'Fetch.fulfillRequest', { requestId: 'job-1' }), error => error === refusal);
  refusal = new Error('Chrome command timeout: Fetch.fulfillRequest (10000 ms)');
  await assert.rejects(page.answer('network-1', 'Fetch.fulfillRequest', { requestId: 'job-1' }), error => error === refusal);
  refusal = null;
  assert.equal(await page.answer('network-5', 'Fetch.fulfillRequest', { requestId: 'job-5' }), true);
  // Closing the page stops recording cancellations.
  await page.close();
  browser.emit('Network.loadingFailed', { requestId: 'network-6', canceled: true });
  refusal = invalid;
  await assert.rejects(page.answer('network-6', 'Fetch.fulfillRequest', { requestId: 'job-6' }, 50), error => error === invalid);
});

test('a late genuine interception error still fails the scenario (Codex PR #331)', async () => {
  const invalid = new CommandError('Fetch.fulfillRequest', { code: -32602, message: 'Invalid InterceptionId.' });
  const browser = fakeBrowser(method => { if (method === 'Fetch.fulfillRequest') throw invalid; return setup(method); });
  const page = await pageFor(browser, viewport);
  const routes = routeTracker();
  // A refusal with no page cancellation: `answer` waits out its grace period
  // before it rethrows, longer than the 100 ms a scenario used to allow.
  routes.track(page.answer('network-1', 'Fetch.fulfillRequest', { requestId: 'job-1' }, 300));
  await delay(100);
  assert.deepEqual(routes.errors, [], 'not reported yet when the scenario used to assert');
  assert.deepEqual(await routes.settle(), ['Fetch.fulfillRequest refused (CDP -32602): Invalid InterceptionId.']);
  // A handler started while the scenario settles is waited for as well.
  const late = routeTracker();
  late.track(delay(50).then(() => late.track(delay(50).then(() => { throw new TypeError('/api/private 0123'); }))));
  assert.deepEqual(await late.settle(), ['TypeError raised by the interceptor']);
  // Handlers that finish cleanly report nothing; one that never finishes fails the settle.
  const clean = routeTracker();
  clean.track(delay(20));
  assert.deepEqual(await clean.settle(), []);
  const stuck = routeTracker();
  stuck.track(new Promise(() => {}));
  await assert.rejects(stuck.settle(50), { message: 'Interception handlers did not settle within 50 ms' });
});

const refusal = (method, code, message) => new CommandError(method, { code, message });

test('finish disables interception, then reports errors started after the last settle (#334)', async () => {
  const sent = [];
  const command = async method => { sent.push(method); return {}; };
  const routes = routeTracker();
  routes.track(Promise.reject(new TypeError('/api/early 0123')));
  assert.deepEqual(await routes.settle(), ['TypeError raised by the interceptor']);
  // A genuine error from a handler started after that settle: the scenario
  // used to have asserted already, so it landed unseen before the page closed.
  routes.track(delay(30).then(() => { throw new TypeError('/api/late 0123'); }));
  // Answers the teardown itself refuses are not errors.
  routes.track(Promise.reject(refusal('Fetch.fulfillRequest', -32000, 'Fetch domain is not enabled')));
  routes.track(Promise.reject(refusal('Fetch.failRequest', -32000, 'Fetch domain is not enabled')));
  // A handler's answer refused because the target went away is not excused:
  // finish runs before the page closes, so that is a genuine failure.
  routes.track(Promise.reject(refusal('Fetch.failRequest', -32001, 'Session with given id not found.')));
  assert.deepEqual(await routes.finish(command), ['Fetch.failRequest refused (CDP -32001): Session with given id not found.',
    'TypeError raised by the interceptor'], 'only the late genuine errors, once');
  // Offline first, so a request still paused is released to no network; then no handler starts.
  assert.deepEqual(sent, ['Network.emulateNetworkConditions', 'Fetch.disable']);
  // Nothing new since: nothing reported, even though the earlier errors are kept.
  assert.deepEqual(await routes.finish(command), []);
  assert.equal(routes.errors.length, 5);
});

test('finish never throws and keeps its own failures value-free (#334)', async () => {
  // A page already gone refuses the teardown commands: teardown-induced, not an error.
  const gone = async method => { throw refusal(method, -32001, 'Session with given id not found.'); };
  assert.deepEqual(await routeTracker().finish(gone), []);
  // Any other refusal of the teardown is reported, without its message.
  const refused = async method => { if (method === 'Fetch.disable') throw refusal(method, -32602, 'Invalid parameters 0123'); };
  assert.deepEqual(await routeTracker().finish(refused), ['Fetch.disable refused (CDP -32602)']);
  // A handler that never finishes fails the finish instead of hanging it.
  const stuck = routeTracker();
  stuck.track(new Promise(() => {}));
  assert.deepEqual(await stuck.finish(async () => ({}), 50), ['Interception handlers did not settle within 50 ms']);
  // A finish with no settle before it reports every error.
  const fresh = routeTracker();
  fresh.track(Promise.reject(new Error('Chrome was closed.')));
  assert.deepEqual(await fresh.finish(async () => ({})), ['Chrome was closed.']);
});

test('only the teardown\'s own refusals are allow-listed (#334)', () => {
  const described = (method, code, message) => describeCommandError(refusal(method, code, message));
  for (const allowed of [
    described('Fetch.fulfillRequest', -32000, 'Fetch domain is not enabled'),
    described('Fetch.failRequest', -32000, 'Fetch domain is not enabled'),
    // A target already gone is excused only for finish's own commands.
    described('Fetch.disable', -32001, 'Session with given id not found.'),
    described('Network.emulateNetworkConditions', -32001, 'Session with given id not found.'),
    described('Network.emulateNetworkConditions', -32000, 'Target closed.'),
    described('Fetch.disable', -32000, 'Inspected target navigated or closed'),
  ]) assert.equal(isTeardownError(allowed), true, allowed);
  for (const genuine of [
    // A request the page did not cancel: Chrome dropped it for another reason.
    described('Fetch.fulfillRequest', -32602, 'Invalid InterceptionId.'),
    described('Fetch.fulfillRequest', -32602, 'Invalid header'),
    described('Fetch.fulfillRequest', -32602, 'Fetch domain is not enabled'),
    described('Fetch.disable', -32000, 'Fetch domain is not enabled'),
    // A handler's answer refused because its target went away (#334 review).
    described('Fetch.fulfillRequest', -32001, 'Session with given id not found.'),
    described('Fetch.failRequest', -32000, 'Target closed.'),
    described('Fetch.continueRequest', -32000, 'Inspected target navigated or closed'),
    described('Runtime.evaluate', -32001, 'Session with given id not found.'),
    'TypeError raised by the interceptor',
    'Chrome was closed.',
    'Chrome command timeout: Fetch.fulfillRequest (10000 ms)',
    'Interception handlers did not settle within 15000 ms',
  ]) assert.equal(isTeardownError(genuine), false, genuine);
});

test('an abandoned request fails unless the scenario names it; a mutation only by its exact path (#334)', () => {
  const invite = { method: 'POST', path: '/api/admin/principals' };
  const reload = { method: 'GET', path: '/api/admin/principals' };
  // By default nothing may be abandoned, a read included.
  assert.deepEqual(unexpectedAbandoned([]), []);
  assert.deepEqual(unexpectedAbandoned([invite, reload]), ['POST /api/admin/principals', 'GET /api/admin/principals']);
  // A named request may be abandoned; the method is part of the name.
  assert.deepEqual(unexpectedAbandoned([invite, reload], [invite]), ['GET /api/admin/principals']);
  assert.deepEqual(unexpectedAbandoned([invite], [reload]), ['POST /api/admin/principals']);
  assert.deepEqual(unexpectedAbandoned([invite], [{ method: 'POST', path: '/api/admin/principals/' }]), ['POST /api/admin/principals']);
  // A read may be named by a pattern (a global or sticky flag keeps no state between requests).
  const views = { method: 'GET', path: /^\/api\/mock\/(?:timeline|presence)$/g };
  assert.deepEqual(unexpectedAbandoned([{ method: 'GET', path: '/api/mock/timeline' }, { method: 'GET', path: '/api/mock/timeline' },
    { method: 'GET', path: '/api/mock/presence' }, { method: 'POST', path: '/api/mock/timeline' }], [views]), ['POST /api/mock/timeline']);
  // A mutation may not be covered by a pattern, nor any method by a wildcard.
  assert.throws(() => unexpectedAbandoned([invite], [{ method: 'POST', path: /^\/api\// }]), /mutation by its exact path only/);
  for (const entry of [{ method: '*', path: '/api/x' }, { method: 'post', path: '/api/x' }, { path: '/api/x' }, null]) {
    assert.throws(() => unexpectedAbandoned([], [entry]), /exact HTTP method/);
  }
  for (const path of ['api/x', undefined, 3]) assert.throws(() => unexpectedAbandoned([], [{ method: 'GET', path }]), /a path or a RegExp/);
});

test('click finds and clicks the element in one evaluation', () => {
  const run = element => new Function('element', `return ${clickWhenEnabled('element')}`)(element);
  let clicks = 0;
  assert.equal(run(undefined), false, 'a missing element (a list re-rendering) is waited for, not a TypeError');
  assert.equal(run({ disabled: true, click() { clicks++; } }), false);
  assert.equal(clicks, 0);
  assert.equal(run({ disabled: false, click() { clicks++; } }), true);
  assert.equal(clicks, 1);
});
