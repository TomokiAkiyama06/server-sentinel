import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { APP_CSP, SHELL_CSP } from './policy.mjs';

/**
 * Local build preview only, never an authorized deployment/dashboard server.
 *
 * Serves the sign-in shell at `/` (with `/s.js`, `/s.css`) and the dashboard
 * at `/app/` from `dist/`, using the paths and content types in
 * `dist/manifest.json`. It has no session and no API: `/api/session` and every
 * other path are an empty 404, so the shell shows its form and a ceremony
 * ends in the shell's generic message. The real routes, session check and
 * headers are the Main Server's (S5b).
 */
export function routes(manifest) {
  const table = new Map();
  for (const [path, { type }] of Object.entries(manifest.files)) {
    let url;
    if (path === 'shell/index.html') url = '/';
    else if (path.startsWith('shell/')) url = `/${path.slice('shell/'.length)}`;
    else if (path === 'app/index.html') url = '/app/';
    else url = `/${path}`;
    const csp = path === 'shell/index.html' ? SHELL_CSP : path === 'app/index.html' ? APP_CSP : "default-src 'none'; frame-ancestors 'none'";
    table.set(url, { file: `dist/${path}`, type, csp });
  }
  return table;
}

export function createPreviewServer(manifest) {
  let table;
  return createServer(async (request, response) => {
    try {
      table ??= routes(manifest ?? JSON.parse(await readFile('dist/manifest.json', 'utf8')));
    } catch { response.writeHead(503).end(); return; }
    const entry = table.get(request.url?.split('?')[0]);
    if (!entry || request.method !== 'GET') { response.writeHead(404).end(); return; }
    try {
      const body = await readFile(entry.file);
      response.writeHead(200, {
        'Content-Type': entry.type, 'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
        'Content-Security-Policy': entry.csp,
      }).end(body);
    } catch { response.writeHead(503).end(); }
  });
}
if (import.meta.main) {
  createPreviewServer().listen(4173, '127.0.0.1', () => {
    process.stdout.write('Local preview: http://127.0.0.1:4173/ (sign-in) and /app/ (dashboard)\n');
  });
}
