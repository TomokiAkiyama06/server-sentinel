import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

/** Minimal CDP adapter for synthetic tests; no runtime dependency or browser download. */
export async function launchChrome() {
  const profile = await mkdtemp(join(tmpdir(), 'server-sentinel-browser-'));
  const child = spawn(process.env.SERVERSENTINEL_BROWSER_EXECUTABLE || 'google-chrome', [
    '--headless=new', '--remote-debugging-pipe', `--user-data-dir=${profile}`,
    '--no-first-run', '--no-default-browser-check', '--disable-background-networking',
    '--disable-component-update', '--disable-default-apps', '--disable-sync',
    'about:blank',
  ], { stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'] });
  let id = 0;
  let buffered = '';
  const pending = new Map();
  const listeners = new Map();
  let stopped;
  function fail(error) {
    stopped = error;
    for (const { reject } of pending.values()) reject(error);
    pending.clear();
  }
  child.on('error', () => fail(new Error('Chrome is unavailable; install/provide a browser executable.')));
  child.on('exit', () => fail(new Error('Chrome exited before the command completed.')));
  child.stdio[4].on('data', data => {
    buffered += data.toString();
    let end;
    while ((end = buffered.indexOf('\0')) !== -1) {
      const message = JSON.parse(buffered.slice(0, end));
      buffered = buffered.slice(end + 1);
      if (message.id) {
        const promise = pending.get(message.id);
        pending.delete(message.id);
        if (promise) message.error ? promise.reject(new Error(message.error.message)) : promise.resolve(message.result);
      } else for (const listener of listeners.get(message.method) || []) listener(message.params, message.sessionId);
    }
  });
  const command = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
    if (stopped) { reject(stopped); return; }
    const commandId = ++id;
    const timeout = setTimeout(() => { pending.delete(commandId); reject(new Error(`Chrome command timeout: ${method}`)); }, 10000);
    pending.set(commandId, {
      resolve(value) { clearTimeout(timeout); resolve(value); },
      reject(error) { clearTimeout(timeout); reject(error); },
    });
    child.stdio[3].write(JSON.stringify({ id: commandId, method, params, ...(sessionId ? { sessionId } : {}) }) + '\0');
  });
  return {
    command,
    on(method, listener) {
      if (!listeners.has(method)) listeners.set(method, new Set());
      listeners.get(method).add(listener);
      return () => listeners.get(method).delete(listener);
    },
    async close() {
      if (child.exitCode === null) child.kill('SIGTERM');
      await delay(200);
      if (child.exitCode === null) child.kill('SIGKILL');
      await rm(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
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
