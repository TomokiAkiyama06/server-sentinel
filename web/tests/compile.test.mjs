import test from 'node:test';
import assert from 'node:assert/strict';
import { access, link, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
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
