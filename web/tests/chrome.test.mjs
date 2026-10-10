import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { launchChrome } from './chrome.mjs';

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
