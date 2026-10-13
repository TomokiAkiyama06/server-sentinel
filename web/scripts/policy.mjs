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

// The dashboard at `/app/` (the policy formerly in its meta element, plus
// frame-ancestors, which only a header can carry).
export const APP_CSP = [
  "default-src 'none'", "script-src 'self'", "style-src 'self'", "connect-src 'self'",
  "img-src 'self'", "font-src 'self'", "base-uri 'none'", "form-action 'none'",
  "frame-ancestors 'none'",
].join('; ');

/** Content types written into dist/manifest.json, by file extension. */
export const CONTENT_TYPES = new Map([
  ['.html', 'text/html; charset=utf-8'],
  ['.js', 'text/javascript; charset=utf-8'],
  ['.css', 'text/css; charset=utf-8'],
  ['.svg', 'image/svg+xml'],
  ['.txt', 'text/plain; charset=utf-8'],
]);
