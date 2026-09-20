import { build } from 'esbuild';
import { mkdir } from 'node:fs/promises';

export async function compile(entry, outfile, platform = 'node') {
  await mkdir('build', { recursive: true });
  await build({
    entryPoints: [entry], outfile, bundle: true, format: 'esm', platform,
    target: 'es2022', ...(platform === 'node' ? { packages: 'external' } : {}),
    define: { 'process.env.NODE_ENV': '"production"' },
  });
}
