import { build } from 'esbuild';
import { mkdir, mkdtemp, rename, rm } from 'node:fs/promises';
import { basename, join } from 'node:path';

// node --test runs test files in parallel processes that compile the same
// shared modules. Build into a private directory and rename the module into
// place, so a concurrent import never observes a truncated or partial file.
export async function compile(entry, outfile, platform = 'node') {
  await mkdir('build', { recursive: true });
  const directory = await mkdtemp(join('build', '.compile-'));
  try {
    const temporary = join(directory, basename(outfile));
    await build({
      entryPoints: [entry], outfile: temporary, bundle: true, format: 'esm', platform,
      target: 'es2022', ...(platform === 'node' ? { packages: 'external' } : {}),
      define: { 'process.env.NODE_ENV': '"production"' },
    });
    await rename(temporary, outfile);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
