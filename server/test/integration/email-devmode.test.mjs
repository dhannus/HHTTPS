// D8: without SMTP_* env and without a sendmail binary the server must fall
// back to dev mode and surface the 6-digit code in the API response.
import test from 'node:test';
import assert from 'node:assert/strict';
import { startServer, pgAvailable } from '../helpers/server.mjs';
import { sql, closeDb } from '../helpers/db.mjs';

test('POST /hhttps/email/send answers devMode:true with a 6-digit devCode', { skip: !pgAvailable() && 'TEST_PG_HOST not set' }, async (t) => {
  const srv = await startServer({ env: { SMTP_HOST: '', SMTP_USER: '', SMTP_PASS: '' } });
  t.after(async () => { await srv.stop(); await closeDb(); });

  const start = await srv.api('/hhttps/session/start', { method: 'POST', body: {} });
  assert.equal(start.status, 200, start.text);
  const { sessionId } = start.json;
  assert.ok(sessionId);

  const send = await srv.api('/hhttps/email/send', {
    method: 'POST',
    body: { sessionId, email: 'devmode@example.org' },
  });
  assert.equal(send.status, 200, send.text);
  assert.equal(send.json.devMode, true);
  assert.match(String(send.json.devCode), /^\d{6}$/);

  // The verification row was persisted (hash only) — visible via the db helper.
  const rows = await sql('SELECT 1 FROM email_verifications WHERE session_id = $1', [sessionId]);
  assert.equal(rows.length, 1);
});
