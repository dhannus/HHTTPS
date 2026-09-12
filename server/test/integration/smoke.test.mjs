// Integration smoke test: the harness boots server.js against TEST_PG_HOST
// and GET /hhttps/info answers 200 with a version string.
import test from 'node:test';
import assert from 'node:assert/strict';
import { startServer, pgAvailable } from '../helpers/server.mjs';

test('GET /hhttps/info returns 200 and a version', { skip: !pgAvailable() && 'TEST_PG_HOST not set' }, async () => {
  const srv = await startServer();
  try {
    const { status, json } = await srv.api('/hhttps/info');
    assert.equal(status, 200);
    assert.equal(typeof json.version, 'string');
    assert.ok(json.version.length > 0);
  } finally {
    await srv.stop();
  }
});
