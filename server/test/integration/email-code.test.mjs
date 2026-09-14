// T2 / AK-23, AK-24: /hhttps/email/confirm-code tolerates spaces/dashes around
// and inside the 6-digit code and rejects anything that is not 6 digits.
import test from 'node:test';
import assert from 'node:assert/strict';
import { startServer, pgAvailable } from '../helpers/server.mjs';
import { closeDb } from '../helpers/db.mjs';
import { freshEmail, newSession, sendCode, confirmCode, createTracker } from '../helpers/identity-flow.mjs';

const skip = !pgAvailable() && 'TEST_PG_HOST not set';

test('confirm-code tolerates a space inside the code, rejects 5 digits, tolerates padding', { skip }, async (t) => {
  const srv = await startServer({ env: { SMTP_HOST: '', SMTP_USER: '', SMTP_PASS: '' } });
  const track = createTracker();
  t.after(async () => { await track.cleanup(); await srv.stop(); await closeDb(); });

  async function sessionWithCode() {
    const sessionId = await newSession(srv, {}, track);
    const { devCode } = await sendCode(srv, sessionId, freshEmail('code'), {}, track);
    assert.match(String(devCode), /^\d{6}$/);
    return { sessionId, devCode: String(devCode) };
  }

  // 1) "123 456" → accepted (AK-23)
  {
    const { sessionId, devCode } = await sessionWithCode();
    const spaced = devCode.slice(0, 3) + ' ' + devCode.slice(3);
    const r = await confirmCode(srv, sessionId, spaced);
    assert.equal(r.status, 200, r.text);
    assert.equal(r.json.verified, true);
    track.add({ userId: r.json.userId });
  }

  // 2) "12345" → 400 (AK-24)
  {
    const { sessionId } = await sessionWithCode();
    const r = await confirmCode(srv, sessionId, '12345');
    assert.equal(r.status, 400, r.text);
  }

  // 3) " 123456 " → accepted (AK-23)
  {
    const { sessionId, devCode } = await sessionWithCode();
    const r = await confirmCode(srv, sessionId, ' ' + devCode + ' ');
    assert.equal(r.status, 200, r.text);
    assert.equal(r.json.verified, true);
    track.add({ userId: r.json.userId });
  }
});
