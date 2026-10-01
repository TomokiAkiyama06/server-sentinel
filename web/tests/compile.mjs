import { build } from 'esbuild';
import { mkdir, rename, rm, writeFile } from 'node:fs/promises';

// `node --test` runs test files in parallel processes and several of them
// compile the same entry to the same outfile. Writing in place lets a
// concurrent importer load a truncated module (every export undefined), so each
// output is written to a process-unique file and atomically renamed into place.
export async function compile(entry, outfile, platform = 'node') {
  await mkdir('build', { recursive: true });
  const result = await build({
    entryPoints: [entry], outfile, bundle: true, format: 'esm', platform, write: false,
    target: 'es2022', ...(platform === 'node' ? { packages: 'external' } : {}),
    define: { 'process.env.NODE_ENV': '"production"' },
  });
  for (const output of result.outputFiles) {
    const temporary = `${output.path}.${process.pid}.tmp`;
    try {
      await writeFile(temporary, output.contents);
      await rename(temporary, output.path);
    } finally {
      await rm(temporary, { force: true });
    }
  }
}
