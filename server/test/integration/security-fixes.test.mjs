// Regression tests for the round-1 security fixes (docs/specs/email-anchored-identity/verifikation.md, F-1..F-8).
// Runs server.js as a child process (HTTP) and asserts against the same Postgres via SQL.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { startServer, pgAvailable } from '../helpers/server.mjs';
import { sql, closeDb, TEST_PEPPER } from '../helpers/db.mjs';
import { rnd, freshEmail as mkEmail, newSession as startSession, sendCode, confirmCode, createTracker } from '../helpers/identity-flow.mjs';
import { emailAnchorHash } from '../../identity.js';

const skip = !pgAvailable() && 'TEST_PG_HOST not set';
const PEPPER = TEST_PEPPER; // the harnessed server's pepper (helpers/server.mjs)

const freshEmail = (tag) => mkEmail(`sec-${tag}`);

let srv;
const track = createTracker();
const clientIds = new Set();
const credentialIds = new Set();

test.before(async () => {
  if (skip) return;
  srv = await startServer({ env: { SMTP_HOST: '', SMTP_USER: '', SMTP_PASS: '' } });
});

test.after(async () => {
  if (skip) return;
  const ids = [...clientIds];
  if (ids.length) {
    await sql('DELETE FROM authorization_codes WHERE client_id = ANY($1)', [ids]);
    await sql('DELETE FROM oauth_clients WHERE client_id = ANY($1)', [ids]);
  }
  await track.cleanup(); // sessions go first — they reference the credentials below
  const creds = [...credentialIds];
  if (creds.length) await sql('DELETE FROM credentials WHERE credential_id = ANY($1)', [creds]);
  await srv.stop();
  await closeDb();
});

function track_(email, userId) { track.add({ email, userId }); }

const newSession = () => startSession(srv, {}, track);
const confirm = (sessionId, code) => confirmCode(srv, sessionId, code);

/** /email/send in dev mode (asserts 200); the address is tracked for removal. */
const send = (sessionId, email, extra = {}) => sendCode(srv, sessionId, email, extra, track);

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
  track_(A, c.json.userId);
  assert.equal(await anchorCount(A), 1);
});

// ─── F-3 (S-4): no fail-open dev mode without EMAIL_DEV_MODE=1 ──────────────

test('F-3/S-4: without EMAIL_DEV_MODE the code is never returned — 503 email_transport_unavailable', { skip }, async (t) => {
  // Separate boot: no SMTP, no sendmail binary in this environment, dev mode NOT enabled.
  const prod = await startServer({ env: { SMTP_HOST: '', SMTP_USER: '', SMTP_PASS: '', EMAIL_DEV_MODE: '' } });
  t.after(() => prod.stop());
  const sessionId = await startSession(prod, {}, track);
  const A = freshEmail('f3');
  track.add({ email: A });
  const s = await prod.api('/hhttps/email/send', { method: 'POST', body: { sessionId, email: A } });
  assert.equal(s.status, 503, s.text);
  assert.equal(s.json.error, 'email_transport_unavailable');
  assert.equal(s.json.devCode, undefined, 'no devCode');
  assert.equal(s.json.devToken, undefined, 'no devToken');
  assert.equal(s.json.devMode, undefined, 'no devMode flag');
});

// ─── F-5 (S-7): role is whitelisted before it reaches the mail ──────────────

test('F-5/S-7: an unknown role is replaced by citizen — the payload never reaches the mail pipeline', { skip }, async () => {
  const sessionId = await newSession();
  const A = freshEmail('f5');
  const payload = '<img src=x onerror=alert(1)>';
  const s = await srv.api('/hhttps/email/send', { method: 'POST', body: { sessionId, email: A, role: payload } });
  assert.equal(s.status, 200, s.text);
  track_(A);
  // The dev-mode log line prints the role that went into the mail renderer.
  assert.ok(!srv.logs().includes(payload), 'raw payload must not appear in the mail pipeline (dev log)');
});

// The email limiter (30 requests / 60 min per IP, in-process) also counts
// /session/start. Everything above already used ~2/3 of it, so the remaining
// groups run against a fresh server process (same DB, same env).
test('(harness) fresh server process for F-6..F-8', { skip }, async () => {
  await srv.stop();
  srv = await startServer({ env: { SMTP_HOST: '', SMTP_USER: '', SMTP_PASS: '' } });
});

// ─── F-6 (K-5/S-6): identity conflicts answer 409, never 500 ────────────────

test('F-6/K-5: a second address in an already anchored session → 409 email_already_bound (not 500)', { skip }, async () => {
  const sessionId = await newSession();
  const A = freshEmail('k5a'); const B = freshEmail('k5b');

  const sa = await send(sessionId, A);
  const ca = await confirm(sessionId, sa.devCode);
  assert.equal(ca.status, 200, ca.text);
  track_(A, ca.json.userId);

  const sb = await send(sessionId, B);
  const cb = await confirm(sessionId, sb.devCode);
  assert.equal(cb.status, 409, cb.text);
  assert.equal(cb.json.error, 'email_already_bound');
  assert.equal(await anchorCount(B), 0, 'no anchor for B');
  const [row] = await sql('SELECT user_id FROM sessions WHERE session_id = $1', [sessionId]);
  assert.equal(row.user_id, ca.json.userId, 'session keeps the first anchor');
});

test('F-6/K-5: a session carrying a passkey credential is never rebound to a foreign anchor → 409 identity_conflict', { skip }, async () => {
  // Victim: email A anchored to U_A.
  const s1 = await newSession();
  const A = freshEmail('k5c');
  const sa = await send(s1, A);
  const ca = await confirm(s1, sa.devCode);
  assert.equal(ca.status, 200, ca.text);
  track_(A, ca.json.userId);

  // Second session with a (simulated) passkey credential for another user.
  const s2 = await newSession();
  const [before] = await sql('SELECT user_id FROM sessions WHERE session_id = $1', [s2]);
  const credId = 'cred-' + rnd();
  await sql(`INSERT INTO credentials (credential_id, user_id, public_key, counter) VALUES ($1, $2, '\\x00', 0)`, [credId, before.user_id]);
  credentialIds.add(credId);
  await sql('UPDATE sessions SET credential_id = $2 WHERE session_id = $1', [s2, credId]);

  const sb = await send(s2, A);
  const cb = await confirm(s2, sb.devCode);
  assert.equal(cb.status, 409, cb.text);
  assert.equal(cb.json.error, 'identity_conflict');
  const [after] = await sql('SELECT user_id, email_verified FROM sessions WHERE session_id = $1', [s2]);
  assert.equal(after.user_id, before.user_id, 'session userId unchanged');
  assert.equal(after.email_verified, false);
});

// ─── F-8 (K-8/S-9b): /oauth/approve enforces allowed_scopes ─────────────────

const REDIRECT_URI = 'http://localhost/cb';

async function createClient(allowedScopes) {
  const clientId = `test-sec-${rnd()}`;
  await sql(
    `INSERT INTO oauth_clients
       (client_id, client_secret_hash, name, homepage_url, redirect_uris, allowed_scopes,
        subject_type, verified, is_active, verification_status)
     VALUES ($1, NULL, $2, $3, $4, $5, 'pairwise', TRUE, TRUE, 'verified')`,
    [clientId, `SEC test client ${clientId}`, 'http://localhost', JSON.stringify([REDIRECT_URI]), JSON.stringify(allowedScopes)]
  );
  clientIds.add(clientId);
  return clientId;
}

async function hhttpsToken() {
  const sessionId = await newSession();
  const A = freshEmail('f8');
  const s = await send(sessionId, A);
  const c = await confirm(sessionId, s.devCode);
  assert.equal(c.status, 200, c.text);
  track_(A, c.json.userId);
  const d = await srv.api('/hhttps/role/declare', { method: 'POST', body: { sessionId } });
  assert.equal(d.status, 200, d.text);
  return d.json.hhttps.token;
}

async function approve(token, clientId, scope) {
  const challenge = crypto.createHash('sha256').update(crypto.randomBytes(32)).digest('base64url');
  return srv.api('/hhttps/oauth/approve', {
    method: 'POST',
    body: { token, client_id: clientId, redirect_uri: REDIRECT_URI, scope,
            code_challenge: challenge, code_challenge_method: 'S256' }
  });
}

test('F-8/K-8: approve with a scope the client may not request → 400 invalid_scope, no code row', { skip }, async () => {
  const token = await hhttpsToken();
  const clientId = await createClient(['openid', 'role']); // no `email`

  const denied = await approve(token, clientId, 'openid email');
  assert.equal(denied.status, 400, denied.text);
  assert.equal(denied.json.error, 'invalid_scope');

  const unknown = await approve(token, clientId, 'openid does-not-exist');
  assert.equal(unknown.status, 400, unknown.text);
  assert.equal(unknown.json.error, 'invalid_scope');

  const rows = await sql('SELECT 1 FROM authorization_codes WHERE client_id = $1', [clientId]);
  assert.equal(rows.length, 0, 'no authorization code was issued');

  // Sanity: an allowed scope set still works.
  const ok = await approve(token, clientId, 'openid role');
  assert.equal(ok.status, 200, ok.text);
  assert.ok(new URL(ok.json.redirect).searchParams.get('code'));
});
