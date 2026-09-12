// T4 / AK-1, AK-2, AK-6, AK-7, AK-8, AK-16: confirming an email binds the
// session to the stable identity anchor (userId + pseudonym) and fills the
// plaintext claims cache. Runs server.js as a child process (HTTP) and asserts
// against the same Postgres via SQL.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { startServer, pgAvailable } from '../helpers/server.mjs';
import { sql, closeDb } from '../helpers/db.mjs';
import { emailAnchorHash, sanitizePseudonym } from '../../identity.js';

const skip = !pgAvailable() && 'TEST_PG_HOST not set';
const PEPPER = 'test-pepper'; // matches testEnv() in helpers/server.mjs

const rnd = () => crypto.randomBytes(5).toString('hex');
const freshEmail = () => `t4-${rnd()}@example.org`;

let srv;
const cleanup = { hashes: new Set(), userIds: new Set() };

test.before(async () => {
  if (skip) return;
  srv = await startServer({ env: { SMTP_HOST: '', SMTP_USER: '', SMTP_PASS: '' } });
});

test.after(async () => {
  if (skip) return;
  const hashes = [...cleanup.hashes]; const userIds = [...cleanup.userIds];
  if (hashes.length) await sql('DELETE FROM identity_anchors WHERE email_hash = ANY($1)', [hashes]);
  if (userIds.length) await sql('DELETE FROM identity_claims_cache WHERE user_id = ANY($1)', [userIds]);
  await srv.stop();
  await closeDb();
});

function track(email, userId) {
  cleanup.hashes.add(emailAnchorHash(email, PEPPER));
  if (userId) cleanup.userIds.add(userId);
}

async function newSession(body = {}) {
  const r = await srv.api('/hhttps/session/start', { method: 'POST', body });
  assert.equal(r.status, 200, r.text);
  return r.json.sessionId;
}

async function send(sessionId, email, extra = {}) {
  const r = await srv.api('/hhttps/email/send', { method: 'POST', body: { sessionId, email, ...extra } });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.json.devMode, true, 'dev mode expected (no SMTP)');
  return r.json;
}

async function confirm(sessionId, code) {
  return srv.api('/hhttps/email/confirm-code', { method: 'POST', body: { sessionId, code } });
}

async function sessionUserId(sessionId) {
  const rows = await sql('SELECT user_id, pseudonym FROM sessions WHERE session_id = $1', [sessionId]);
  return rows[0];
}

test('AK-1/AK-7: first confirmation creates an anchor, generated pseudonym, bound session, claims cache (AK-16)', { skip }, async () => {
  const email = freshEmail();
  const a = await newSession();
  const { devCode } = await send(a, email);

  const r = await confirm(a, devCode);
  assert.equal(r.status, 200, r.text);
  assert.equal(r.json.verified, true);
  assert.ok(r.json.userId, 'userId in response');
  assert.match(r.json.pseudonym, /^iamhmn_[a-z0-9]{10}$/);
  assert.equal(r.json.anchorCreated, true);
  assert.ok(r.json.methods.includes('email'));
  track(email, r.json.userId);

  const s = await sessionUserId(a);
  assert.equal(s.user_id, r.json.userId, 'session bound to anchor userId');
  assert.equal(s.pseudonym, r.json.pseudonym);

  const anchor = await sql('SELECT user_id, pseudonym FROM identity_anchors WHERE email_hash = $1', [emailAnchorHash(email, PEPPER)]);
  assert.equal(anchor.length, 1);
  assert.equal(anchor[0].user_id, r.json.userId);
  assert.equal(anchor[0].pseudonym, r.json.pseudonym);

  const cache = await sql('SELECT email, pseudonym, verified_methods FROM identity_claims_cache WHERE user_id = $1', [r.json.userId]);
  assert.equal(cache.length, 1);
  assert.equal(cache[0].email, email.toLowerCase());
  assert.equal(cache[0].pseudonym, r.json.pseudonym);
  assert.ok(JSON.parse(cache[0].verified_methods).includes('email'));
});

test('AK-2/AK-8: same email (other case/whitespace) in a new session rebinds to the stored userId and keeps the pseudonym', { skip }, async () => {
  const email = freshEmail();
  const a = await newSession();
  const first = await confirm(a, (await send(a, email)).devCode);
  assert.equal(first.status, 200, first.text);
  track(email, first.json.userId);

  const b = await newSession();
  const bBefore = await sessionUserId(b);
  assert.notEqual(bBefore.user_id, first.json.userId, 'fresh session starts with a random userId');

  const variant = `  ${email.toUpperCase()} `;
  const second = await confirm(b, (await send(b, variant, { pseudonym: 'Anna' })).devCode);
  assert.equal(second.status, 200, second.text);
  assert.equal(second.json.userId, first.json.userId);
  assert.equal(second.json.pseudonym, first.json.pseudonym);
  assert.equal(second.json.anchorCreated, false);

  const s = await sessionUserId(b);
  assert.equal(s.user_id, first.json.userId);
  assert.equal(s.pseudonym, first.json.pseudonym);
});

test('AK-6: a user-supplied pseudonym is sanitized and stored in the anchor', { skip }, async () => {
  const email = freshEmail();
  const raw = 'Max <b>x</b>';
  const expected = sanitizePseudonym(raw); // 'Max bxb' — tags stripped char-wise, letters survive
  assert.match(expected, /^Max b/);
  assert.notEqual(expected, raw);

  const c = await newSession();
  const r = await confirm(c, (await send(c, email, { pseudonym: raw })).devCode);
  assert.equal(r.status, 200, r.text);
  track(email, r.json.userId);
  assert.equal(r.json.pseudonym, expected);

  const anchor = await sql('SELECT pseudonym FROM identity_anchors WHERE email_hash = $1', [emailAnchorHash(email, PEPPER)]);
  assert.equal(anchor[0].pseudonym, expected);
  assert.equal((await sessionUserId(c)).pseudonym, expected);
});

test('AK-1 via magic link: /hhttps/email/verify binds the session and redirects with pseudonym', { skip }, async () => {
  const email = freshEmail();
  const d = await newSession();
  const { devToken } = await send(d, email);
  assert.ok(devToken, 'devToken expected');

  const res = await fetch(`${srv.baseUrl}/hhttps/email/verify?token=${encodeURIComponent(devToken)}&session=${d}`, { redirect: 'manual' });
  assert.equal(res.status, 302);
  const loc = res.headers.get('location');
  assert.match(loc, /email_verify=success/);
  const url = new URL(loc, srv.baseUrl);
  const pseudonym = url.searchParams.get('pseudonym');
  assert.match(pseudonym, /^iamhmn_[a-z0-9]{10}$/);

  const anchor = await sql('SELECT user_id, pseudonym FROM identity_anchors WHERE email_hash = $1', [emailAnchorHash(email, PEPPER)]);
  assert.equal(anchor.length, 1);
  track(email, anchor[0].user_id);
  const s = await sessionUserId(d);
  assert.equal(s.user_id, anchor[0].user_id);
  assert.equal(s.pseudonym, pseudonym);
  assert.equal(anchor[0].pseudonym, pseudonym);
});
