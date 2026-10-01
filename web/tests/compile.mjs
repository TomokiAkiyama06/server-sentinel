import { build } from 'esbuild';
import { mkdir, rename, writeFile } from 'node:fs/promises';

// Test files run in parallel processes and share build outputs, so each output
// is written to a private temporary file and renamed into place: a concurrent
// import sees either the previous complete module or the new one, never an
// empty, truncated file.
export async function compile(entry, outfile, platform = 'node') {
  await mkdir('build', { recursive: true });
  const result = await build({
    entryPoints: [entry], outfile, bundle: true, format: 'esm', platform, write: false,
    target: 'es2022', ...(platform === 'node' ? { packages: 'external' } : {}),
    define: { 'process.env.NODE_ENV': '"production"' },
  });
  for (const file of result.outputFiles) {
    const temporary = `${file.path}.${process.pid}.tmp`;
    await writeFile(temporary, file.contents);
    await rename(temporary, file.path);
  }
}
