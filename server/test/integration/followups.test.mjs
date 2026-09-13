// Follow-up issues of PR #19 (email-anchored identity).
//
// #22: POST /hhttps/email/confirm-code must load the session BEFORE it
//      consumes the verification code. Previously verifyEmailCode() marked the
//      row `used` first, so a confirm with an unknown/expired sessionId burnt
//      the code of a session it did not even belong to — the user could never
//      confirm on the real session with the code they received.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { startServer, pgAvailable } from '../helpers/server.mjs';
import { sql, closeDb } from '../helpers/db.mjs';
import { freshEmail, newSession as startSession, sendCode, confirmCode, createTracker } from '../helpers/identity-flow.mjs';

const skip = !pgAvailable() && 'TEST_PG_HOST not set';
const SERVER_ENV = { SMTP_HOST: '', SMTP_USER: '', SMTP_PASS: '', GITHUB_CLIENT_ID: '', GITHUB_CLIENT_SECRET: '' };

let srv;
const track = createTracker();

test.before(async () => {
  if (skip) return;
  srv = await startServer({ env: SERVER_ENV });
});

test.after(async () => {
  if (skip) return;
  await track.cleanup();
  await srv.stop();
  await closeDb();
});

const newSession = () => startSession(srv, {}, track);
const send = (sessionId, email) => sendCode(srv, sessionId, email, {}, track);
const confirm = (sessionId, code) => confirmCode(srv, sessionId, code);

async function usedFlag(sessionId) {
  const [r] = await sql('SELECT used FROM email_verifications WHERE session_id = $1', [sessionId]);
  assert.ok(r, 'verification row for the session exists');
  return r.used;
}

// ─── #22 ────────────────────────────────────────────────────────────────────

test('#22: confirm-code with an unknown sessionId → 404 and does NOT consume the code of another session', { skip }, async () => {
  const sessionA = await newSession();
  const { devCode } = await send(sessionA, freshEmail('fu22'));

  // Unknown session + a valid code (of session A): the session check must win
  // and the verification row of A must stay unused.
  const r = await confirm(crypto.randomUUID(), devCode);
  assert.equal(r.status, 404, r.text);
  assert.equal(await usedFlag(sessionA), false, 'the code of session A is still unused');

  // The same code still confirms the real session.
  const ok = await confirm(sessionA, devCode);
  assert.equal(ok.status, 200, ok.text);
  assert.equal(ok.json.verified, true);
  track.add({ userId: ok.json.userId });
  assert.equal(await usedFlag(sessionA), true, 'now the code is consumed');
});

test('#22: confirm-code with an unknown sessionId and a garbage code → 404 (session is checked first)', { skip }, async () => {
  const r = await confirm(crypto.randomUUID(), '123456');
  assert.equal(r.status, 404, r.text);
});
