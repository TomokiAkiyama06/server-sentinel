import { build } from 'esbuild';
import { createHash } from 'node:crypto';
import { mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { extname, join, relative, resolve, sep } from 'node:path';
import { CONTENT_TYPES } from './policy.mjs';

/**
 * Two separately built documents (Issue #10 phase 2 S5a, Owner decision S5-1):
 *
 * - `dist/shell/` — the pre-credential sign-in shell served at `/`, `/s.js`
 *   and `/s.css`. Its only inputs are `src/signin/**` and the string-free
 *   `src/shared/webauthn.ts`; anything else (React, the i18n catalog, a
 *   dashboard module, any package) fails the build.
 * - `dist/app/` — the dashboard served under `/app/` to a signed-in session.
 *
 * `dist/manifest.json` lists every served file with its SHA-256, size and
 * content type (format in web/README.md). The output is a pure function of
 * the sources and the locked esbuild: two builds are byte-identical.
 */

const SHELL_INPUTS = /^src\/signin\/[^/]+\.(ts|css)$/;
const SHELL_SHARED = new Set(['src/shared/webauthn.ts']);
const APP_PACKAGES = /^node_modules\/(react|react-dom|scheduler)\//;

export const SHELL_BUDGET = { html: 2 * 1024, js: 12 * 1024, css: 3 * 1024 };

function shellInputAllowed(input) {
  return SHELL_INPUTS.test(input) || SHELL_SHARED.has(input);
}

export function checkShellInputs(metafile) {
  const inputs = Object.keys(metafile.inputs);
  for (const input of inputs) {
    if (!shellInputAllowed(input)) throw new Error(`Sign-in shell input not allowed: ${input}`);
  }
  return inputs;
}

function checkAppInputs(metafile) {
  const inputs = Object.keys(metafile.inputs);
  for (const input of inputs) {
    if (input.includes('node_modules/') && !APP_PACKAGES.test(input)) {
      throw new Error('Unreviewed dependency in runtime bundle');
    }
  }
  return inputs;
}

const common = { bundle: true, minify: true, write: false, metafile: true, logLevel: 'silent' };

function collapse(html) {
  return html.replace(/>\s+</g, '><').trim() + '\n';
}

/** Build both documents into `outdir` (default `dist`) and return the inputs and manifest. */
export async function buildAll(outdir = 'dist') {
  const root = resolve('.');
  const target = resolve(outdir);
  if (target === root || !target.startsWith(root + sep)) throw new Error('outdir must be inside web/');

  const shellScript = await build({
    ...common, entryPoints: ['src/signin/main.ts'], outfile: join(target, 'shell/s.js'),
    format: 'esm', target: ['es2022'], legalComments: 'none', charset: 'utf8',
  });
  const shellStyle = await build({
    ...common, entryPoints: ['src/signin/style.css'], outfile: join(target, 'shell/s.css'),
    legalComments: 'none',
  });
  const shellInputs = [...checkShellInputs(shellScript.metafile), ...checkShellInputs(shellStyle.metafile)];

  const app = await build({
    ...common, entryPoints: ['src/main.tsx'], outfile: join(target, 'app/app.js'),
    format: 'esm', target: ['es2022'], define: { 'process.env.NODE_ENV': '"production"' },
    legalComments: 'external',
  });
  const appInputs = checkAppInputs(app.metafile);

  const files = new Map();
  for (const result of [shellScript, shellStyle, app]) {
    for (const file of result.outputFiles) files.set(relative(target, file.path).split(sep).join('/'), file.contents);
  }
  files.set('shell/index.html', Buffer.from(collapse(await readFile('src/signin/index.html', 'utf8'))));
  files.set('app/index.html', await readFile('src/app/index.html'));
  files.set('app/icon.svg', await readFile('src/icon.svg'));
  // Production runtime attribution ships beside the bundle, not from a CDN.
  for (const name of ['react', 'react-dom', 'scheduler']) {
    files.set(`app/${name}-LICENSE.txt`, await readFile(`node_modules/${name}/LICENSE`));
  }

  const manifest = { files: {} };
  for (const path of [...files.keys()].sort()) {
    const type = CONTENT_TYPES.get(extname(path));
    if (!type) throw new Error(`No content type for ${path}`);
    const contents = files.get(path);
    manifest.files[path] = {
      sha256: createHash('sha256').update(contents).digest('hex'), size: contents.length, type,
    };
  }

  await rm(target, { recursive: true, force: true });
  for (const [path, contents] of files) {
    await mkdir(join(target, path, '..'), { recursive: true });
    await writeFile(join(target, path), contents);
  }
  await writeFile(join(target, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  return { manifest, shellInputs, appInputs };
}

/** Every regular file under `directory`, as sorted `/`-joined relative paths. */
export async function listFiles(directory) {
  const entries = await readdir(directory, { recursive: true, withFileTypes: true });
  return entries.filter(entry => entry.isFile())
    .map(entry => relative(directory, join(entry.parentPath, entry.name)).split(sep).join('/')).sort();
}

if (import.meta.main) await buildAll();
