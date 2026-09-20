import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createPreviewServer } from '../scripts/preview.mjs';

const scenario = process.argv[2];
assert.ok(['normal', 'error'].includes(scenario));
const server = createPreviewServer();
server.listen(0, '127.0.0.1');
await once(server, 'listening');
const origin = `http://127.0.0.1:${server.address().port}`;
try {
  if (scenario === 'normal') {
    const response = await fetch(origin);
    assert.equal(response.status, 200);
    assert.match(await response.text(), /lang="ja"/);
    for (const asset of ['app.js', 'app.css']) {
      const assetResponse = await fetch(`${origin}/assets/${asset}`);
      assert.equal(assetResponse.status, 200);
      assert.ok((await assetResponse.text()).length > 100);
    }
  } else {
    for (const path of ['/api/live/synthetic-source', '/api/recordings', '/api/session', '/missing', '/tests/harness.tsx']) {
      const response = await fetch(origin + path);
      assert.equal(response.status, 404);
      assert.equal(await response.text(), '');
    }
    const response = await fetch(origin, { method: 'POST', body: 'synthetic invalid input' });
    assert.equal(response.status, 404);
  }
  process.stdout.write(`Local static preview ${scenario} smoke passed\n`);
} finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
