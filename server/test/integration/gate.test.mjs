// T5 / AK-4, AK-5, AK-9, AK-10..AK-13: email-first gate, stable passkey user
// handle and pseudonym + method-flag claims in HHTTPS tokens. Runs server.js as
// a child process (HTTP) with EUDI_VERIFIER_SECRET = 'test-secret' and no
// GitHub OAuth app configured.
//
// AK-5 (passkey auth binds the session to cred.userId) cannot be exercised over
// HTTP without a real authenticator. It is covered by AK-4 (the WebAuthn user
// handle IS the stable userId, so register/finish stores cred.userId = userId)
// plus the existing code path in /hhttps/webauthn/auth/finish, which creates
// the session with `userId: stored.userId || cred.userId` — auth/start stores
// `userId` only when the client sent one, otherwise null → cred.userId wins.
// The tester verifies that code location by inspection.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { startServer, pgAvailable } from '../helpers/server.mjs';
import { sql, closeDb } from '../helpers/db.mjs';
import { emailAnchorHash } from '../../identity.js';

const skip = !pgAvailable() && 'TEST_PG_HOST not set';
const PEPPER = 'test-pepper';          // matches testEnv() in helpers/server.mjs
const EUDI_SECRET = 'test-secret';     // matches testEnv() in helpers/server.mjs

const rnd = () => crypto.randomBytes(5).toString('hex');
const freshEmail = () => `t5-${rnd()}@example.org`;

let srv;
const cleanup = { hashes: new Set(), userIds: new Set() };

test.before(async () => {
  if (skip) return;
  srv = await startServer({ env: { SMTP_HOST: '', SMTP_USER: '', SMTP_PASS: '', GITHUB_CLIENT_ID: '', GITHUB_CLIENT_SECRET: '' } });
});

test.after(async () => {
  if (skip) return;
  const hashes = [...cleanup.hashes]; const userIds = [...cleanup.userIds];
  if (hashes.length) await sql('DELETE FROM identity_anchors WHERE email_hash = ANY($1)', [hashes]);
  if (userIds.length) await sql('DELETE FROM identity_claims_cache WHERE user_id = ANY($1)', [userIds]);
  await srv.stop();
  await closeDb();
});

async function newSession() {
  const r = await srv.api('/hhttps/session/start', { method: 'POST', body: {} });
  assert.equal(r.status, 200, r.text);
  return r.json.sessionId;
}

/** Full email flow: returns { sessionId, userId, pseudonym } of an email-verified session. */
async function verifiedSession(extra = {}) {
  const sessionId = await newSession();
  const email = freshEmail();
  const s = await srv.api('/hhttps/email/send', { method: 'POST', body: { sessionId, email, ...extra } });
  assert.equal(s.status, 200, s.text);
  assert.equal(s.json.devMode, true, 'dev mode expected (no SMTP)');
  const c = await srv.api('/hhttps/email/confirm-code', { method: 'POST', body: { sessionId, code: s.json.devCode } });
  assert.equal(c.status, 200, c.text);
  cleanup.hashes.add(emailAnchorHash(email, PEPPER));
  cleanup.userIds.add(c.json.userId);
  return { sessionId, userId: c.json.userId, pseudonym: c.json.pseudonym };
}

function decodeJwtPayload(token) {
  const [, payload] = String(token).split('.');
  return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
}

function eidAssertion(sessionId, nonce, iat) {
  const canonical = JSON.stringify({ sessionId, eidVerified: true, nonce, iat });
  return crypto.createHmac('sha256', EUDI_SECRET).update(canonical).digest('hex');
}

function assertGate(r) {
  assert.equal(r.status, 403, r.text);
  assert.equal(r.json?.error, 'email_verification_required', r.text);
}

// ─── AK-10: webauthn/register/start ─────────────────────────────────────────

test('AK-10: register/start with a session without confirmed email → 403 email_verification_required', { skip }, async () => {
  const sessionId = await newSession();
  const r = await srv.api('/hhttps/webauthn/register/start', { method: 'POST', body: { sessionId } });
  assertGate(r);
});

test('W-19: register/start without sessionId → 400 sessionId required (anonymous legacy path is gone)', { skip }, async () => {
  const r = await srv.api('/hhttps/webauthn/register/start', { method: 'POST', body: { userId: crypto.randomUUID() } });
  assert.equal(r.status, 400, r.text);
  assert.equal(r.json?.error, 'sessionId required', r.text);
});

test('register/start with an unknown sessionId → 404', { skip }, async () => {
  const r = await srv.api('/hhttps/webauthn/register/start', { method: 'POST', body: { sessionId: crypto.randomUUID() } });
  assert.equal(r.status, 404, r.text);
});

// ─── AK-4: user handle = stable userId ──────────────────────────────────────

test('AK-4: after email confirmation register/start returns options.user.id == session userId and user.name == pseudonym', { skip }, async () => {
  const { sessionId, userId, pseudonym } = await verifiedSession();
  const r = await srv.api('/hhttps/webauthn/register/start', {
    method: 'POST', body: { sessionId, userId: 'legacy-should-be-ignored' }
  });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.json.userId, userId, 'response userId is the stable session userId (legacy body userId ignored)');
  const handle = Buffer.from(r.json.options.user.id, 'base64url').toString('utf8');
  assert.equal(handle, userId, 'WebAuthn user handle == stable userId');
  assert.equal(r.json.options.user.name, pseudonym);
});

// ─── AK-11: verify/github/start ─────────────────────────────────────────────

test('AK-11: verify/github/start without confirmed email → 403 JSON (gate runs before isGithubConfigured)', { skip }, async () => {
  const sessionId = await newSession();
  const res = await fetch(`${srv.baseUrl}/hhttps/verify/github/start?session=${sessionId}`, { redirect: 'manual' });
  const text = await res.text();
  assert.equal(res.status, 403, text);
  assert.equal(JSON.parse(text).error, 'email_verification_required');
});

// ─── AK-12: eid/upgrade ─────────────────────────────────────────────────────

test('AK-12: eid/upgrade with a valid assertion but no confirmed email → 403, no token', { skip }, async () => {
  const sessionId = await newSession();
  const nonce = rnd(); const iat = Date.now();
  const r = await srv.api('/hhttps/eid/upgrade', {
    method: 'POST', body: { sessionId, nonce, iat, assertion: eidAssertion(sessionId, nonce, iat) }
  });
  assertGate(r);
  assert.equal(r.json.hhttps, undefined, 'no token issued');
});

test('AK-12/AK-9: eid/upgrade with confirmed email → 200, token carries eudi_verified, email_verified, pseudonym', { skip }, async () => {
  const { sessionId, userId, pseudonym } = await verifiedSession();
  const nonce = rnd(); const iat = Date.now();
  const r = await srv.api('/hhttps/eid/upgrade', {
    method: 'POST', body: { sessionId, nonce, iat, assertion: eidAssertion(sessionId, nonce, iat) }
  });
  assert.equal(r.status, 200, r.text);
  const p = decodeJwtPayload(r.json.hhttps.token);
  assert.equal(p.userId, userId);
  assert.equal(p.eudi_verified, true);
  assert.equal(p.email_verified, true);
  assert.equal(p.passkey_verified, false);
  assert.equal(p.pseudonym, pseudonym);
  assert.ok(p.verified_methods.includes('email') && p.verified_methods.includes('eudi'));
  const rp = decodeJwtPayload(r.json.hhttps.refreshToken);
  assert.equal(rp.pseudonym, pseudonym, 'refresh token carries pseudonym');
});

// ─── AK-13 / AK-9: role/declare ─────────────────────────────────────────────

test('AK-13: role/declare without confirmed email → 403 email_verification_required', { skip }, async () => {
  const sessionId = await newSession();
  const r = await srv.api('/hhttps/role/declare', { method: 'POST', body: { sessionId } });
  assertGate(r);
});

test('AK-13/AK-9: role/declare with confirmed email → 200, token carries pseudonym + method flags', { skip }, async () => {
  const { sessionId, userId, pseudonym } = await verifiedSession();
  const r = await srv.api('/hhttps/role/declare', {
    method: 'POST', body: { sessionId, verificationData: { pseudonym: 'TypedLater' } }
  });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.json.verification.pseudonym, pseudonym, 'account pseudonym wins over the typed legacy value');
  const p = decodeJwtPayload(r.json.hhttps.token);
  assert.equal(p.userId, userId);
  assert.equal(p.pseudonym, pseudonym);
  assert.equal(p.email_verified, true);
  assert.equal(p.passkey_verified, false);
  assert.equal(p.github_verified, false);
  assert.equal(p.eudi_verified, false);
  assert.ok(Array.isArray(p.verified_methods) && p.verified_methods.includes('email'));
  assert.equal(decodeJwtPayload(r.json.hhttps.refreshToken).pseudonym, pseudonym);
});

// ─── AK-9: token/refresh ────────────────────────────────────────────────────

test('AK-9: token/refresh issues a new access token with pseudonym and method flags', { skip }, async () => {
  const { sessionId, pseudonym } = await verifiedSession();
  const d = await srv.api('/hhttps/role/declare', { method: 'POST', body: { sessionId } });
  assert.equal(d.status, 200, d.text);
  const r = await srv.api('/hhttps/token/refresh', { method: 'POST', body: { refreshToken: d.json.hhttps.refreshToken } });
  assert.equal(r.status, 200, r.text);
  const p = decodeJwtPayload(r.json.token);
  assert.equal(p.pseudonym, pseudonym);
  assert.equal(p.email_verified, true);
  assert.ok(p.verified_methods.includes('email'));
});
