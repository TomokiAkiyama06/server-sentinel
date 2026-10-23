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
        if (promise) message.error ? promise.reject(new CommandError(promise.method, message.error)) : promise.resolve(message.result);
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
      method,
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

/** A command Chrome answered with a protocol error (as opposed to a timeout or a closed pipe). */
export class CommandError extends Error {
  constructor(method, { code, message }) {
    super(String(message ?? ''));
    this.name = 'CommandError';
    this.method = method;
    this.code = code;
  }
}

// Protocol error messages that are fixed strings in Chrome's DevTools handlers
// and carry no request, page or input value.
const COMMAND_MESSAGES = [
  /^Invalid InterceptionId\.?$/,
  /^Invalid state for continueInterceptedRequest\.?$/,
  /^Session with given id not found\.?$/,
  /^Target closed\.?$/,
  /^Inspected target navigated or closed$/,
  /^Fetch domain is not enabled\.?$/,
];
const METHOD = /^[A-Z][A-Za-z]{0,31}\.[a-z][A-Za-z]{0,63}$/;
// Errors this adapter raises itself, whose only variable parts are a CDP
// method name, a configured number or a process status.
const ADAPTER_MESSAGES = [
  /^Chrome command timeout: [A-Z][A-Za-z]{0,31}\.[a-z][A-Za-z]{0,63} \(\d+ ms\)$/,
  /^Chrome was closed\.$/,
  /^Chrome exited before the command completed \(code (?:-?\d+|null), signal (?:[A-Z0-9]+|null)\)\.$/,
];

/**
 * A value-free description of an error raised while answering an intercepted
 * request (#326): for a protocol error the CDP method and numeric code, plus
 * the message only when it is one of the fixed strings above; for this
 * adapter's own timeout/closed errors the message; anything else (a handler
 * bug, which may quote request data) is reduced to its error class.
 */
export function describeCommandError(error) {
  if (error instanceof CommandError) {
    const method = METHOD.test(error.method ?? '') ? error.method : 'unknown method';
    const code = Number.isInteger(error.code) ? error.code : 'unknown';
    const message = COMMAND_MESSAGES.some(shape => shape.test(error.message)) ? `: ${error.message}` : '';
    return `${method} refused (CDP ${code})${message}`;
  }
  if (error instanceof Error && ADAPTER_MESSAGES.some(shape => shape.test(error.message))) return error.message;
  const name = error instanceof Error && new RegExp(`^${IDENTIFIER}$`).test(error.name) ? error.name : 'non-Error value';
  return `${name} raised by the interceptor`;
}

// Interception errors a scenario's own teardown causes (#334): an answer
// sent after `finish` disabled the Fetch domain, or after the page's target
// went away. Matched against `describeCommandError` output, so they stay
// value-free; every other error found by `finish` fails the scenario.
const TEARDOWN_ERRORS = [
  /^Fetch\.(?:fulfillRequest|failRequest|continueRequest) refused \(CDP -32000\): Fetch domain is not enabled\.?$/,
  /^[A-Z][A-Za-z]{0,31}\.[a-z][A-Za-z]{0,63} refused \(CDP -?\d+\): (?:Session with given id not found|Target closed|Inspected target navigated or closed)\.?$/,
];

/** True for a described interception error that only a scenario's teardown causes (#334). */
export function isTeardownError(description) {
  return TEARDOWN_ERRORS.some(shape => shape.test(description));
}

/**
 * Tracks the detached handlers a scenario starts for `Fetch.requestPaused`
 * (Codex PR #331). A handler may finish long after the page has moved on:
 * a slow synthetic answer, or `answer` waiting up to its grace period before
 * it rethrows a genuine refusal. `settle` waits for every handler, including
 * one started while it waits, so such an error is reported before the
 * scenario asserts and closes the page instead of landing after it. The
 * errors are kept value-free (`describeCommandError`). A handler still
 * running after `timeoutMilliseconds` fails the settle.
 *
 * `finish` closes the gap after the scenario's last `settle` (#334): the page
 * may still start requests while the scenario finishes its checks. It takes
 * the page offline (so a request still paused is released to no network),
 * disables the Fetch domain (so no further handler starts), waits for every
 * handler again and returns the errors not yet reported by an earlier
 * `settle`, minus the ones the teardown itself causes (`isTeardownError`).
 * It never throws: a refused or failed teardown command is returned as an
 * error unless it, too, is teardown-induced.
 */
export function routeTracker() {
  const running = new Set();
  const errors = [];
  let reported = 0;
  async function settle(timeoutMilliseconds = 15000) {
    const deadline = Date.now() + timeoutMilliseconds;
    let timer;
    try {
      while (running.size) {
        const remaining = deadline - Date.now();
        if (remaining <= 0) throw new Error(`Interception handlers did not settle within ${timeoutMilliseconds} ms`);
        await Promise.race([Promise.all(running), new Promise(resolve => { timer = setTimeout(resolve, remaining); })]);
        clearTimeout(timer);
      }
    } finally { clearTimeout(timer); }
    reported = errors.length;
    return errors;
  }
  return {
    errors,
    track(handler) {
      const settled = Promise.resolve(handler)
        .catch(error => { errors.push(describeCommandError(error)); })
        .finally(() => running.delete(settled));
      running.add(settled);
    },
    settle,
    async finish(command, timeoutMilliseconds = 15000) {
      const from = reported;
      const late = [];
      for (const [method, params] of [
        ['Network.emulateNetworkConditions', { offline: true, latency: 0, downloadThroughput: -1, uploadThroughput: -1 }],
        ['Fetch.disable', {}],
      ]) {
        try { await command(method, params); } catch (error) { late.push(describeCommandError(error)); }
      }
      try { await settle(timeoutMilliseconds); } catch (error) { late.push(error.message); }
      return [...errors.slice(from), ...late].filter(description => !isTeardownError(description));
    },
  };
}

const ABANDONABLE_METHOD = /^[A-Z]{3,7}$/;
const READ_METHODS = new Set(['GET', 'HEAD']);

/**
 * The requests a scenario saw abandoned by the page that it did not expect
 * (#334). By default no request may be abandoned: a page that cancels a
 * request mid-flight (a view change, a reload, pagehide) must be named by the
 * scenario in `expected`, as `{ method, path }` with an exact HTTP method and
 * either an exact pathname or a RegExp over it. A RegExp may only cover reads
 * (GET/HEAD); a mutation (POST and the rest) may be abandoned only where the
 * scenario names its exact path, so a regression that aborts a change on
 * unmount is not hidden by a broad pattern. `abandoned` holds
 * `{ method, path }` records; the result is `METHOD path` strings.
 */
export function unexpectedAbandoned(abandoned, expected = []) {
  for (const entry of expected) {
    if (!ABANDONABLE_METHOD.test(entry?.method ?? '')) throw new TypeError('expectAbandoned needs an exact HTTP method');
    const exact = typeof entry.path === 'string' && entry.path.startsWith('/');
    if (!exact && !(entry.path instanceof RegExp)) throw new TypeError('expectAbandoned needs a path or a RegExp');
    if (!exact && !READ_METHODS.has(entry.method)) throw new TypeError('expectAbandoned names a mutation by its exact path only');
  }
  const allowed = ({ method, path }) => expected.some(entry => entry.method === method
    && (entry.path instanceof RegExp ? new RegExp(entry.path.source, entry.path.flags.replace(/[gy]/g, '')).test(path) : entry.path === path));
  return abandoned.filter(item => !allowed(item)).map(({ method, path }) => `${method} ${path}`);
}

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

/**
 * An expression for `wait` that finds the element, and clicks it only when it
 * is present and enabled, in the same evaluation. Finding it in one
 * evaluation and clicking it in the next raced a re-render in between (PR #331
 * CI: the access screen unmounts its list while it reloads after a change, so
 * the second lookup found nothing).
 */
export function clickWhenEnabled(find) {
  return `(() => { const el = ${find}; if (!el || el.disabled) return false; el.click(); return true; })()`;
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
  // Requests the page itself cancelled (an AbortController on a view change,
  // or a navigation), by network id, for `answer` below.
  const cancelled = new Set();
  const stopCancelled = browser.on('Network.loadingFailed', ({ requestId, canceled }, from) => {
    if (from === sessionId && canceled) cancelled.add(requestId);
  });
  /**
   * Answers an intercepted request (`Fetch.fulfillRequest` / `Fetch.failRequest`)
   * and resolves true once Chrome accepted the answer. When the page cancelled
   * the request while it was paused, Chrome has already dropped the
   * interception and refuses the answer with `Invalid InterceptionId` (#326);
   * that resolves false, but only once Chrome has also reported the request as
   * cancelled (`Network.loadingFailed` with `canceled`, normally sent before the
   * refusal; up to `graceMilliseconds` are allowed for it). Every other failure,
   * and an `Invalid InterceptionId` without a page cancellation, is rethrown.
   */
  async function answer(networkId, method, params, graceMilliseconds = 1000) {
    try {
      await command(method, params);
      return true;
    } catch (error) {
      if (!(error instanceof CommandError) || !/^Invalid InterceptionId\.?$/.test(error.message) || !networkId) throw error;
      for (let waited = 0; !cancelled.has(networkId) && waited < graceMilliseconds; waited += 25) await delay(25);
      if (!cancelled.has(networkId)) throw error;
      return false;
    }
  }
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
    command, evaluate, wait, navigate, answer, sessionId,
    async heading(title) { await wait(`Array.from(document.querySelectorAll('h1')).some(el => el.textContent === ${JSON.stringify(title)})`); },
    async click(title) {
      await wait(clickWhenEnabled(`Array.from(document.querySelectorAll('nav button')).find(el => el.textContent === ${JSON.stringify(title)})`));
    },
    async enabled(title) {
      return evaluate(`!Array.from(document.querySelectorAll('nav button')).find(el => el.textContent === ${JSON.stringify(title)}).disabled`);
    },
    async close() {
      stopCancelled();
      await browser.command('Target.disposeBrowserContext', { browserContextId });
    },
  };
}
