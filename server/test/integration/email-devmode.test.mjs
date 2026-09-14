// D8: without SMTP_* env and without a sendmail binary the server must fall
// back to dev mode and surface the 6-digit code in the API response.
import test from 'node:test';
import assert from 'node:assert/strict';
import { startServer, pgAvailable } from '../helpers/server.mjs';
import { sql, closeDb } from '../helpers/db.mjs';
import { freshEmail, newSession, createTracker } from '../helpers/identity-flow.mjs';

test('POST /hhttps/email/send answers devMode:true with a 6-digit devCode', { skip: !pgAvailable() && 'TEST_PG_HOST not set' }, async (t) => {
  const srv = await startServer({ env: { SMTP_HOST: '', SMTP_USER: '', SMTP_PASS: '' } });
  const track = createTracker();
  t.after(async () => { await track.cleanup(); await srv.stop(); await closeDb(); });

  const sessionId = await newSession(srv, {}, track);
  assert.ok(sessionId);

  const email = freshEmail('devmode');
  const send = await srv.api('/hhttps/email/send', { method: 'POST', body: { sessionId, email } });
  track.add({ email });
  assert.equal(send.status, 200, send.text);
  assert.equal(send.json.devMode, true);
  assert.match(String(send.json.devCode), /^\d{6}$/);

  // The verification row was persisted (hash only) — visible via the db helper.
  const rows = await sql('SELECT 1 FROM email_verifications WHERE session_id = $1', [sessionId]);
  assert.equal(rows.length, 1);
});
