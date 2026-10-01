import test from 'node:test';
import assert from 'node:assert/strict';
import { access, link, mkdir, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { compile } from './compile.mjs';

// `node --test` runs files in parallel and several of them compile the same
// entry to the same outfile. Rewriting the existing file in place lets a
// concurrent importer load a truncated module (every export undefined), so a
// compile must replace the outfile atomically instead of mutating its inode.
test('compile replaces the bundle atomically instead of rewriting it in place', async () => {
  await mkdir('build', { recursive: true });
  const outfile = 'build/compile-atomic-domain.mjs';
  const observer = 'build/compile-atomic-observer.mjs';
  await rm(outfile, { force: true });
  await rm(observer, { force: true });
  const previous = 'export const previous = true;\n';
  await writeFile(outfile, previous);
  await link(outfile, observer);
  try {
    await compile('src/domain.ts', outfile);
    // A reader holding the previous file still sees it whole; the new bundle is complete.
    assert.equal(await readFile(observer, 'utf8'), previous);
    assert.match(await readFile(outfile, 'utf8'), /\bviews\b/);
    // Only this process's temporary file is checked: parallel test files share build/.
    await assert.rejects(access(`${resolve(outfile)}.${process.pid}.tmp`), { code: 'ENOENT' });
  } finally {
    await rm(outfile, { force: true });
    await rm(observer, { force: true });
  }
});

// `node --test` runs every test file in its own process at the same time, and
// several files compile the same shared modules (for example build/i18n.mjs).
// A compile that truncates the output in place lets a sibling process import
// an empty module, so outputs must be replaced atomically instead.
test('compile replaces its output atomically instead of truncating it in place', async () => {
  await mkdir('build', { recursive: true });
  const outfile = 'build/compile-atomic-check.mjs';
  await writeFile(outfile, 'export const placeholder = true;\n');
  const before = await stat(outfile);
  await compile('src/i18n.ts', outfile);
  const after = await stat(outfile);
  assert.notEqual(after.ino, before.ino, 'output must be a new file renamed into place');
  const { messages } = await import(`../${outfile}?after=${after.ino}`);
  assert.ok(messages.ja && messages.en);
  const leftovers = (await readdir('build')).filter(name => name.startsWith('compile-atomic-check.mjs.'));
  assert.deepEqual(leftovers, []);
});
