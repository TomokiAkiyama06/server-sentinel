/**
 * Response policy the Main Server is expected to send for the two documents
 * (S5b owns the real headers; the local preview and the browser tests send
 * these). See web/README.md "Build output and manifest".
 */

// The pre-credential sign-in shell at `/`: its own script, style and fetch to
// the same origin only; no image, font, frame, form target or plugin; DOM
// sinks closed by Trusted Types (the shell only assigns `textContent`).
export const SHELL_CSP = [
  "default-src 'none'", "script-src 'self'", "style-src 'self'", "connect-src 'self'",
  "img-src 'none'", "font-src 'none'", "base-uri 'none'", "form-action 'none'",
  "frame-ancestors 'none'", "require-trusted-types-for 'script'", "trusted-types 'none'",
].join('; ');

// The dashboard at `/app/`. The document also carries APP_META_CSP in a meta
// element as defence in depth (the build refuses a document whose meta policy
// differs); the header adds frame-ancestors, which a meta element cannot carry.
export const APP_META_CSP = [
  "default-src 'none'", "script-src 'self'", "style-src 'self'", "connect-src 'self'",
  "img-src 'self'", "font-src 'self'", "base-uri 'none'", "form-action 'none'",
].join('; ');
export const APP_CSP = `${APP_META_CSP}; frame-ancestors 'none'`;

/** Content types written into dist/manifest.json, by file extension. */
export const CONTENT_TYPES = new Map([
  ['.html', 'text/html; charset=utf-8'],
  ['.js', 'text/javascript; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.svg', 'image/svg+xml'],
  ['.txt', 'text/plain; charset=utf-8'],
]);
