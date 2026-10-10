import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const STDERR_TAIL_BYTES = 8192;
const CHROME_ARGUMENTS = [
  '--headless=new', '--remote-debugging-pipe',
  '--no-first-run', '--no-default-browser-check', '--disable-background-networking',
  '--disable-component-update', '--disable-default-apps', '--disable-sync',
  'about:blank',
];

/**
 * Minimal CDP adapter for synthetic tests; no runtime dependency or browser download.
 *
 * Startup is gated by a bounded readiness probe (`Browser.getVersion`). A
 * Chrome process that does not answer within `readinessTimeoutMs` is
 * terminated and a fresh process with a fresh profile is launched, at most
 * `attempts` times in total (#197: a hung first CDP answer did not recover by
 * waiting longer, so the old 30 s single wait only delayed the failure). A
 * missing executable is not retried, every retry is logged, and the final
 * failure carries each attempt's exit status and stderr tail. Only the
 * startup handshake is retried; commands after readiness keep a plain
 * per-command timeout so real test failures are never masked.
 */
export async function launchChrome(options = {}) {
  const executable = options.executable ?? (process.env.SERVERSENTINEL_BROWSER_EXECUTABLE || 'google-chrome');
  const attempts = options.attempts ?? 3;
  const readinessTimeoutMs = options.readinessTimeoutMs ?? 20000;
  const log = options.log ?? (line => process.stderr.write(`${line}\n`));
  if (!Number.isInteger(attempts) || attempts < 1) throw new Error('attempts must be a positive integer');
  const failures = [];
  for (let attempt = 1; attempt <= attempts; attempt++) {
    const browser = await startChrome(executable, options);
    try {
      const version = await browser.command('Browser.getVersion', {}, undefined, readinessTimeoutMs);
      if (attempt > 1) log(`Chrome answered the DevTools readiness probe on launch attempt ${attempt}/${attempts}.`);
      browser.version = version;
      return browser;
    } catch (error) {
      await browser.close();
      const report = browser.diagnostics(error);
      if (browser.unavailable) throw new Error(`Chrome is unavailable; install/provide a browser executable (${executable}).\n${report}`);
      failures.push(`attempt ${attempt}/${attempts}: ${report}`);
      log(`Chrome launch attempt ${attempt}/${attempts} failed the DevTools readiness probe: ${error.message}`);
    }
  }
  throw new Error(`Chrome did not become ready after ${attempts} launch attempts (readiness timeout ${readinessTimeoutMs} ms each).\n${failures.join('\n')}`);
}

async function startChrome(executable, options) {
  const commandTimeoutMs = options.commandTimeoutMs ?? 10000;
  const terminateGraceMs = options.terminateGraceMs ?? 2000;
  const profile = await mkdtemp(join(tmpdir(), 'server-sentinel-browser-'));
  const child = spawn(executable, [`--user-data-dir=${profile}`, ...CHROME_ARGUMENTS],
    { stdio: ['ignore', 'ignore', 'pipe', 'pipe', 'pipe'] });
  let id = 0;
  let buffered = '';
  let stderrTail = '';
  let unavailable = false;
  const pending = new Map();
  const listeners = new Map();
  let stopped;
  let markExited;
  const exited = new Promise(resolve => { markExited = resolve; });
  function fail(error) {
    stopped ??= error;
    for (const { reject } of pending.values()) reject(error);
    pending.clear();
  }
  child.on('error', error => {
    if (error.code === 'ENOENT' || error.code === 'EACCES') unavailable = true;
    fail(new Error(`Chrome could not be started: ${error.message}`));
    markExited();
  });
  child.on('exit', (code, signal) => {
    fail(new Error(`Chrome exited before the command completed (code ${code}, signal ${signal}).`));
    markExited();
  });
  child.stderr?.on('data', data => {
    stderrTail = (stderrTail + data.toString()).slice(-STDERR_TAIL_BYTES);
  });
  // A broken pipe must surface as a failed command, never as an unhandled
  // stream error that kills the test runner without diagnostics.
  for (const stream of [child.stdio[3], child.stdio[4], child.stderr]) stream?.on('error', error => fail(new Error(`Chrome DevTools pipe failed: ${error.message}`)));
  child.stdio[4]?.on('data', data => {
    buffered += data.toString();
    let end;
    while ((end = buffered.indexOf('\0')) !== -1) {
      let message;
      try { message = JSON.parse(buffered.slice(0, end)); } catch {
        fail(new Error('Chrome sent a malformed DevTools message.'));
        return;
      }
      buffered = buffered.slice(end + 1);
      if (message.id) {
        const promise = pending.get(message.id);
        pending.delete(message.id);
        if (promise) message.error ? promise.reject(new Error(message.error.message)) : promise.resolve(message.result);
      } else for (const listener of listeners.get(message.method) || []) listener(message.params, message.sessionId);
    }
  });
  const command = (method, params = {}, sessionId, timeoutMilliseconds = commandTimeoutMs) => new Promise((resolve, reject) => {
    if (stopped) { reject(stopped); return; }
    const commandId = ++id;
    const timeout = setTimeout(() => {
      pending.delete(commandId);
      reject(new Error(`Chrome command timeout: ${method} (${timeoutMilliseconds} ms)`));
    }, timeoutMilliseconds);
    pending.set(commandId, {
      resolve(value) { clearTimeout(timeout); resolve(value); },
      reject(error) { clearTimeout(timeout); reject(error); },
    });
    child.stdio[3].write(JSON.stringify({ id: commandId, method, params, ...(sessionId ? { sessionId } : {}) }) + '\0');
  });
  const running = () => child.pid !== undefined && child.exitCode === null && child.signalCode === null;
  let closing;
  return {
    command,
    get unavailable() { return unavailable; },
    diagnostics(error) {
      const status = child.pid === undefined ? 'not started'
        : `exit code ${child.exitCode}, signal ${child.signalCode}`;
      const stderr = stderrTail.trim() ? stderrTail.trimEnd() : '(empty)';
      return `${error.message} [${status}]\n--- Chrome stderr (last ${STDERR_TAIL_BYTES} bytes) ---\n${stderr}\n--- end Chrome stderr ---`;
    },
    on(method, listener) {
      if (!listeners.has(method)) listeners.set(method, new Set());
      listeners.get(method).add(listener);
      return () => listeners.get(method).delete(listener);
    },
    close() {
      closing ??= (async () => {
        fail(new Error('Chrome was closed.'));
        if (running()) {
          child.kill('SIGTERM');
          await Promise.race([exited, delay(terminateGraceMs)]);
        }
        if (running()) {
          child.kill('SIGKILL');
          await Promise.race([exited, delay(terminateGraceMs)]);
        }
        await rm(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
      })();
      return closing;
    },
  };
}

export async function pageFor(browser, viewport) {
  const { browserContextId } = await browser.command('Target.createBrowserContext');
  const { targetId } = await browser.command('Target.createTarget', { url: 'about:blank', browserContextId });
  const { sessionId } = await browser.command('Target.attachToTarget', { targetId, flatten: true });
  const command = (method, params) => browser.command(method, params, sessionId);
  await command('Page.enable');
  await command('Runtime.enable');
  await command('Network.enable');
  await command('Network.setBypassServiceWorker', { bypass: true });
  await command('Emulation.setDeviceMetricsOverride', { ...viewport, deviceScaleFactor: 1, mobile: false });
  async function evaluate(expression) {
    const result = await command('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
    if (result.exceptionDetails) throw new Error('Browser evaluation failed');
    return result.result.value;
  }
  async function wait(expression) {
    for (let i = 0; i < 100; i++) {
      if (await evaluate(expression)) return;
      await delay(50);
    }
    throw new Error('Browser DOM assertion timed out');
  }
  return {
    command, evaluate, wait, sessionId,
    async heading(title) { await wait(`Array.from(document.querySelectorAll('h1')).some(el => el.textContent === ${JSON.stringify(title)})`); },
    async click(title) {
      const selector = `Array.from(document.querySelectorAll('nav button')).find(el => el.textContent === ${JSON.stringify(title)})`;
      await wait(`Boolean((${selector}) && !(${selector}).disabled)`);
      await evaluate(`(${selector}).click()`);
    },
    async enabled(title) {
      return evaluate(`!Array.from(document.querySelectorAll('nav button')).find(el => el.textContent === ${JSON.stringify(title)}).disabled`);
    },
    async close() { await browser.command('Target.disposeBrowserContext', { browserContextId }); },
  };
}
