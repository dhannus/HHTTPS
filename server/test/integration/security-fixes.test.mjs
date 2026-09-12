// Regression tests for the round-1 security fixes (docs/specs/email-anchored-identity/verifikation.md, F-1..F-8).
// Runs server.js as a child process (HTTP) and asserts against the same Postgres via SQL.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { startServer, pgAvailable } from '../helpers/server.mjs';
import { sql, closeDb } from '../helpers/db.mjs';
import { emailAnchorHash } from '../../identity.js';

const skip = !pgAvailable() && 'TEST_PG_HOST not set';
const PEPPER = 'test-pepper'; // matches testEnv() in helpers/server.mjs

const rnd = () => crypto.randomBytes(5).toString('hex');
const freshEmail = (tag) => `sec-${tag}-${rnd()}@example.org`;

let srv;
const cleanup = { hashes: new Set(), userIds: new Set(), clientIds: new Set() };

test.before(async () => {
  if (skip) return;
  srv = await startServer({ env: { SMTP_HOST: '', SMTP_USER: '', SMTP_PASS: '' } });
});

test.after(async () => {
  if (skip) return;
  const hashes = [...cleanup.hashes]; const userIds = [...cleanup.userIds]; const clientIds = [...cleanup.clientIds];
  if (clientIds.length) {
    await sql('DELETE FROM authorization_codes WHERE client_id = ANY($1)', [clientIds]);
    await sql('DELETE FROM oauth_clients WHERE client_id = ANY($1)', [clientIds]);
  }
  if (userIds.length) await sql('DELETE FROM identity_claims_cache WHERE user_id = ANY($1)', [userIds]);
  if (hashes.length) await sql('DELETE FROM identity_anchors WHERE email_hash = ANY($1)', [hashes]);
  await srv.stop();
  await closeDb();
});

function track(email, userId) {
  cleanup.hashes.add(emailAnchorHash(email, PEPPER));
  if (userId) cleanup.userIds.add(userId);
}

async function newSession() {
  const r = await srv.api('/hhttps/session/start', { method: 'POST', body: {} });
  assert.equal(r.status, 200, r.text);
  return r.json.sessionId;
}

async function send(sessionId, email, extra = {}) {
  const r = await srv.api('/hhttps/email/send', { method: 'POST', body: { sessionId, email, ...extra } });
  assert.equal(r.status, 200, r.text);
  track(email);
  return r.json;
}

async function confirm(sessionId, code) {
  return srv.api('/hhttps/email/confirm-code', { method: 'POST', body: { sessionId, code } });
}

/** GET /hhttps/email/verify without following the redirect → { status, location } */
async function verifyLink(token, sessionId) {
  const res = await fetch(`${srv.baseUrl}/hhttps/email/verify?token=${encodeURIComponent(token)}&session=${encodeURIComponent(sessionId)}`, { redirect: 'manual' });
  return { status: res.status, location: res.headers.get('location') || '' };
}

async function anchorCount(email) {
  const rows = await sql('SELECT 1 FROM identity_anchors WHERE email_hash = $1', [emailAnchorHash(email, PEPPER)]);
  return rows.length;
}

// ─── F-1 (K-1/S-1, K-2/S-3): anchor binding is tied to the proven address ───

test('F-1/K-1: send A, send B, confirm with code A → 4xx and NO anchor for B', { skip }, async () => {
  const sessionId = await newSession();
  const A = freshEmail('k1a'); const B = freshEmail('k1b');

  const sendA = await send(sessionId, A);
  assert.match(String(sendA.devCode), /^\d{6}$/);
  await send(sessionId, B); // overwrites the email:<sid> context with B

  const c = await confirm(sessionId, sendA.devCode);
  assert.ok(c.status >= 400 && c.status < 500, `expected 4xx, got ${c.status} ${c.text}`);
  assert.equal(await anchorCount(B), 0, 'no anchor for B (code belonged to A)');
  assert.equal(await anchorCount(A), 0, 'no anchor for A either (context is B)');

  const [s] = await sql('SELECT email_verified FROM sessions WHERE session_id = $1', [sessionId]);
  assert.equal(s.email_verified, false, 'session not email-verified');
});

test('F-1/K-1 defence in depth: a still-open row for A cannot bind context B → 409 email_context_mismatch', { skip }, async () => {
  const sessionId = await newSession();
  const A = freshEmail('k1c'); const B = freshEmail('k1d');

  const sendA = await send(sessionId, A);
  await send(sessionId, B);
  // Simulate a row for A that survived the re-send (e.g. a pre-fix DB state).
  const hashA = crypto.createHash('sha256').update(A.toLowerCase()).digest('hex');
  await sql('UPDATE email_verifications SET used = FALSE WHERE session_id = $1 AND email = $2', [sessionId, hashA]);

  const c = await confirm(sessionId, sendA.devCode);
  assert.equal(c.status, 409, c.text);
  assert.equal(c.json.error, 'email_context_mismatch');
  assert.equal(await anchorCount(B), 0);
  assert.equal(await anchorCount(A), 0);
});

test('F-1/K-2: magic link with a foreign session in the URL → session_mismatch, no bind', { skip }, async () => {
  const s1 = await newSession(); const s2 = await newSession();
  const A = freshEmail('k2a'); const B = freshEmail('k2b');

  const sendA = await send(s1, A);   // token T belongs to s1
  await send(s2, B);                 // s2 has its own context (B)
  assert.ok(sendA.devToken, 'devToken present');

  const r = await verifyLink(sendA.devToken, s2);
  assert.ok(r.status >= 300 && r.status < 400, `redirect expected, got ${r.status}`);
  assert.match(r.location, /email_verify=error/, r.location);
  assert.match(r.location, /reason=session_mismatch/, r.location);

  assert.equal(await anchorCount(A), 0);
  assert.equal(await anchorCount(B), 0);
  const [row] = await sql('SELECT email_verified, user_id FROM sessions WHERE session_id = $1', [s2]);
  assert.equal(row.email_verified, false, 's2 must not be email-verified');
});

test('F-1: re-send in the same session invalidates the older verification row', { skip }, async () => {
  const sessionId = await newSession();
  const A = freshEmail('k1e'); const B = freshEmail('k1f');
  await send(sessionId, A);
  await send(sessionId, B);
  const rows = await sql('SELECT used FROM email_verifications WHERE session_id = $1 ORDER BY created_at', [sessionId]);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].used, true, 'row for A is invalidated');
  assert.equal(rows[1].used, false, 'row for B stays open');
});

test('F-1 sanity: the happy path (single send + correct code) still binds', { skip }, async () => {
  const sessionId = await newSession();
  const A = freshEmail('ok');
  const s = await send(sessionId, A);
  const c = await confirm(sessionId, s.devCode);
  assert.equal(c.status, 200, c.text);
  track(A, c.json.userId);
  assert.equal(await anchorCount(A), 1);
});
