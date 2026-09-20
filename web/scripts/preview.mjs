import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';

/** Local build preview only, never an authorized deployment/dashboard server. */
const files = new Map([
  ['/', ['dist/index.html', 'text/html; charset=utf-8']],
  ['/assets/app.js', ['dist/assets/app.js', 'text/javascript; charset=utf-8']],
  ['/assets/app.css', ['dist/assets/app.css', 'text/css; charset=utf-8']],
  ['/assets/icon.svg', ['dist/assets/icon.svg', 'image/svg+xml']],
]);
export function createPreviewServer() {
  return createServer(async (request, response) => {
    const entry = files.get(request.url?.split('?')[0]);
    if (!entry || request.method !== 'GET') { response.writeHead(404).end(); return; }
    try {
      const body = await readFile(entry[0]);
      response.writeHead(200, {
        'Content-Type': entry[1], 'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "frame-ancestors 'none'",
      }).end(body);
    } catch { response.writeHead(503).end(); }
  });
}
if (import.meta.main) {
  createPreviewServer().listen(4173, '127.0.0.1', () => {
    process.stdout.write('Local dashboard preview: http://127.0.0.1:4173\n');
  });
}
