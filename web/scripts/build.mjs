import { build } from 'esbuild';
import { copyFile, mkdir } from 'node:fs/promises';

await mkdir('dist/assets', { recursive: true });
const result = await build({
  entryPoints: ['src/main.tsx'], bundle: true, minify: true,
  outfile: 'dist/assets/app.js', format: 'esm', target: ['es2022'],
  define: { 'process.env.NODE_ENV': '"production"' },
  legalComments: 'external',
  metafile: true,
});
for (const input of Object.keys(result.metafile.inputs)) {
  if (input.includes('node_modules/') && !/^node_modules\/(react|react-dom|scheduler)\//.test(input)) {
    throw new Error('Unreviewed dependency in runtime bundle');
  }
}
await copyFile('index.html', 'dist/index.html');
await copyFile('src/icon.svg', 'dist/assets/icon.svg');
// Production runtime attribution ships beside the bundle, not from a CDN.
await copyFile('node_modules/react/LICENSE', 'dist/react-LICENSE.txt');
await copyFile('node_modules/react-dom/LICENSE', 'dist/react-dom-LICENSE.txt');
await copyFile('node_modules/scheduler/LICENSE', 'dist/scheduler-LICENSE.txt');
