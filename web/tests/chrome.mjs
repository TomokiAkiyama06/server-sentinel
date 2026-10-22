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

const IDENTIFIER = '[A-Za-z_$][\\w$]{0,63}';
// V8 messages whose only variable part is an identifier taken from the test's
// own expression, never page or input text. Anything else is reduced to its
// error class.
const STANDARD_MESSAGES = [
  new RegExp(`^Cannot read properties of (?:null|undefined) \\(reading '${IDENTIFIER}'\\)$`),
  new RegExp(`^Cannot set properties of (?:null|undefined) \\(setting '${IDENTIFIER}'\\)$`),
  new RegExp(`^${IDENTIFIER}(?:\\.${IDENTIFIER}){0,7} is not a function$`),
  new RegExp(`^${IDENTIFIER} is not defined$`),
];

/**
 * A value-free description of a CDP `exceptionDetails` (#322): the error
 * class, plus the engine message only when it has one of the allowlisted V8
 * shapes above. Every other message (which may quote page text, input or an
 * invitation code, e.g. JSON.parse or an application error) is dropped, and a
 * thrown non-Error value is described by its type only.
 */
export function describeException(details) {
  const exception = details?.exception;
  if (exception?.type !== 'object' || exception.subtype !== 'error') {
    return `non-Error value thrown (${exception?.type ?? 'unknown'})`;
  }
  const className = new RegExp(`^${IDENTIFIER}$`).test(exception.className ?? '') ? exception.className : 'Error';
  const first = String(exception.description ?? '').split('\n', 1)[0];
  const message = first.startsWith(`${className}: `) ? first.slice(className.length + 2) : '';
  return STANDARD_MESSAGES.some(shape => shape.test(message)) ? `${className}: ${message}` : className;
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
    if (result.exceptionDetails) throw new Error(`Browser evaluation failed: ${describeException(result.exceptionDetails)}`);
    return result.result.value;
  }
  // A poll may span a navigation the page makes itself (e.g. a redirect to
  // /app/): CDP then refuses the evaluation because the document's context is
  // gone, which is not an answer, so the poll goes on until its deadline. An
  // exception thrown by the expression itself stays fatal. A timeout names the
  // last refusal so a poll stuck in navigation is not mistaken for a false DOM.
  const NAVIGATING = /^(Execution context was destroyed|Cannot find default execution context|Inspected target navigated or closed)\b/;
  async function wait(expression) {
    let refused;
    for (let i = 0; i < 100; i++) {
      try {
        if (await evaluate(expression)) return;
      } catch (error) {
        const navigating = NAVIGATING.exec(error.message);
        if (!navigating) throw error;
        refused = navigating[1];
      }
      await delay(50);
    }
    throw new Error(`Browser DOM assertion timed out${refused ? ` (last CDP refusal while navigating: ${refused})` : ''}`);
  }
  /**
   * Navigates the top frame and resolves once that navigation's document has
   * committed and parsed (DOMContentLoaded). `Page.navigate` answers before the
   * new document has been parsed, so an evaluation sent right after it can run
   * while that document is still loading (#322: `readyState` 'loading', `#m`
   * not parsed yet, so `getElementById('m')` returns null).
   */
  async function navigate(url, timeoutMilliseconds = 10000) {
    // Events may arrive before the command's answer, so every parsed top-level
    // document is recorded by loader and matched once the loader is known.
    let committed;
    let wanted;
    let reached;
    const parsed = new Set();
    const ready = new Promise(resolve => { reached = resolve; });
    const cleanup = [
      browser.on('Page.frameNavigated', ({ frame }, from) => { if (from === sessionId && !frame.parentId) committed = frame.loaderId; }),
      browser.on('Page.domContentEventFired', (_, from) => {
        if (from !== sessionId || !committed) return;
        parsed.add(committed);
        if (committed === wanted) reached();
      }),
    ];
    let timer;
    try {
      const { loaderId, errorText } = await command('Page.navigate', { url });
      if (errorText) throw new Error(`Navigation failed: ${errorText}`);
      if (!loaderId) throw new Error('Navigation started no new document');
      wanted = loaderId;
      if (parsed.has(loaderId)) return;
      await Promise.race([ready, new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`Navigation did not reach DOMContentLoaded within ${timeoutMilliseconds} ms`)), timeoutMilliseconds);
      })]);
    } finally {
      clearTimeout(timer);
      cleanup.forEach(remove => remove());
    }
  }
  return {
    command, evaluate, wait, navigate, sessionId,
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
