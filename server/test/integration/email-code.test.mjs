// T2 / AK-23, AK-24: /hhttps/email/confirm-code tolerates spaces/dashes around
// and inside the 6-digit code and rejects anything that is not 6 digits.
import test from 'node:test';
import assert from 'node:assert/strict';
import { startServer, pgAvailable } from '../helpers/server.mjs';
import { closeDb } from '../helpers/db.mjs';

const skip = !pgAvailable() && 'TEST_PG_HOST not set';

async function sessionWithCode(srv, email) {
  const start = await srv.api('/hhttps/session/start', { method: 'POST', body: {} });
  assert.equal(start.status, 200, start.text);
  const { sessionId } = start.json;
  const send = await srv.api('/hhttps/email/send', { method: 'POST', body: { sessionId, email } });
  assert.equal(send.status, 200, send.text);
  assert.equal(send.json.devMode, true);
  assert.match(String(send.json.devCode), /^\d{6}$/);
  return { sessionId, devCode: String(send.json.devCode) };
}

test('confirm-code tolerates a space inside the code, rejects 5 digits, tolerates padding', { skip }, async (t) => {
  const srv = await startServer({ env: { SMTP_HOST: '', SMTP_USER: '', SMTP_PASS: '' } });
  t.after(async () => { await srv.stop(); await closeDb(); });

  // 1) "123 456" → accepted (AK-23)
  {
    const { sessionId, devCode } = await sessionWithCode(srv, 'code1@example.org');
    const spaced = devCode.slice(0, 3) + ' ' + devCode.slice(3);
    const r = await srv.api('/hhttps/email/confirm-code', { method: 'POST', body: { sessionId, code: spaced } });
    assert.equal(r.status, 200, r.text);
    assert.equal(r.json.verified, true);
  }

  // 2) "12345" → 400 (AK-24)
  {
    const { sessionId } = await sessionWithCode(srv, 'code2@example.org');
    const r = await srv.api('/hhttps/email/confirm-code', { method: 'POST', body: { sessionId, code: '12345' } });
    assert.equal(r.status, 400, r.text);
  }

  // 3) " 123456 " → accepted (AK-23)
  {
    const { sessionId, devCode } = await sessionWithCode(srv, 'code3@example.org');
    const r = await srv.api('/hhttps/email/confirm-code', { method: 'POST', body: { sessionId, code: ' ' + devCode + ' ' } });
    assert.equal(r.status, 200, r.text);
    assert.equal(r.json.verified, true);
  }
});
