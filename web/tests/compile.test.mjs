import test from 'node:test';
import assert from 'node:assert/strict';
import { readdir, stat, writeFile, mkdir } from 'node:fs/promises';
import { compile } from './compile.mjs';

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
