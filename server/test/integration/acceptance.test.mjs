// Tester (Feature email-anchored-identity): acceptance tests that close the
// gaps of the T2..T6 integration suites — negative / boundary cases per AK,
// the machine path through /oauth/approve, AK-21 with a passkey credential
// simulated via SQL, and the spec gaps (marked `todo`, they never fail the
// gate but document the executable reproduction).
// Spec: docs/specs/email-anchored-identity/requirements.md
//
// The email limiter (30 req / 60 min per IP, in-process, counts /session/start,
// /email/send and /email/confirm-code) forces a fresh server process per group.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { startServer, pgAvailable } from '../helpers/server.mjs';
import { sql, closeDb, TEST_PEPPER, TEST_EUDI_SECRET } from '../helpers/db.mjs';
import {
  rnd, freshEmail as mkEmail, newSession as startSession, sendCode, confirmCode,
  verifyEmail, decodeJwtPayload, createTracker,
} from '../helpers/identity-flow.mjs';
import { emailAnchorHash } from '../../identity.js';

const skip = !pgAvailable() && 'TEST_PG_HOST not set';
const REDIRECT_URI = 'http://localhost/cb';
const SERVER_ENV = { SMTP_HOST: '', SMTP_USER: '', SMTP_PASS: '', GITHUB_CLIENT_ID: '', GITHUB_CLIENT_SECRET: '' };

const freshEmail = (tag) => mkEmail(`acc-${tag}`);

let srv;
const track = createTracker();
const clientIds = new Set();
const credentialIds = new Set();
const operatorIds = new Set();

test.before(async () => {
  if (skip) return;
  srv = await startServer({ env: SERVER_ENV });
});

test.after(async () => {
  if (skip) return;
  const ids = [...clientIds];
  if (ids.length) {
    await sql('DELETE FROM authorization_codes WHERE client_id = ANY($1)', [ids]);
    await sql('DELETE FROM connected_platforms WHERE client_id = ANY($1)', [ids]);
    await sql('DELETE FROM oauth_clients WHERE client_id = ANY($1)', [ids]);
  }
  const ops = [...operatorIds];
  if (ops.length) {
    await sql('DELETE FROM tokens WHERE operator_id = ANY($1)', [ops]);
    await sql('DELETE FROM machine_operators WHERE operator_id = ANY($1)', [ops]);
  }
  await track.cleanup(); // sessions first — they reference the credentials
  const creds = [...credentialIds];
  if (creds.length) await sql('DELETE FROM credentials WHERE credential_id = ANY($1)', [creds]);
  await srv.stop();
  await closeDb();
});

/** Fresh server process (rate-limit budget reset). */
async function restart() {
  await srv.stop();
  srv = await startServer({ env: SERVER_ENV });
}

const newSession = (body = {}) => startSession(srv, body, track);
const send = (sessionId, email, extra = {}) => sendCode(srv, sessionId, email, extra, track);
const confirm = (sessionId, code) => confirmCode(srv, sessionId, code);
const verifiedSession = (tag, pseudonym) => verifyEmail(srv, freshEmail(tag), pseudonym, track);

async function sessionRow(sessionId) {
  const [r] = await sql('SELECT user_id, pseudonym, email_verified, credential_id FROM sessions WHERE session_id = $1', [sessionId]);
  return r;
}

async function anchorCount(email) {
  return (await sql('SELECT 1 FROM identity_anchors WHERE email_hash = $1', [emailAnchorHash(email, TEST_PEPPER)])).length;
}

/** Simulated passkey credential for userId (the WebAuthn ceremony itself needs an authenticator). */
async function attachSimulatedPasskey(sessionId, userId) {
  const credId = 'acc-cred-' + rnd();
  await sql(`INSERT INTO credentials (credential_id, user_id, public_key, counter) VALUES ($1, $2, '\\x00', 0)`, [credId, userId]);
  credentialIds.add(credId);
  await sql('UPDATE sessions SET credential_id = $2 WHERE session_id = $1', [sessionId, credId]);
  return credId;
}

async function createClient(allowedScopes = ['openid', 'role', 'email']) {
  const clientId = `test-acc-${rnd()}`;
  await sql(
    `INSERT INTO oauth_clients
       (client_id, client_secret_hash, name, homepage_url, redirect_uris, allowed_scopes,
        subject_type, verified, is_active, verification_status)
     VALUES ($1, NULL, $2, $3, $4, $5, 'pairwise', TRUE, TRUE, 'verified')`,
    [clientId, `ACC test client ${clientId}`, 'http://localhost', JSON.stringify([REDIRECT_URI]), JSON.stringify(allowedScopes)]
  );
  clientIds.add(clientId);
  return clientId;
}

function pkce() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

function approve(token, clientId, scope, challenge) {
  return srv.api('/hhttps/oauth/approve', {
    method: 'POST',
    body: { token, client_id: clientId, redirect_uri: REDIRECT_URI, scope, code_challenge: challenge, code_challenge_method: 'S256' }
  });
}

/** approve → code → token exchange. Returns { code, tokens }. */
async function codeFlow(token, clientId, scope) {
  const { verifier, challenge } = pkce();
  const a = await approve(token, clientId, scope, challenge);
  assert.equal(a.status, 200, a.text);
  const code = new URL(a.json.redirect).searchParams.get('code');
  const t = await srv.api('/hhttps/oauth/token', {
    method: 'POST',
    body: { grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI, client_id: clientId, code_verifier: verifier }
  });
  assert.equal(t.status, 200, t.text);
  return { code, tokens: t.json };
}

async function declare(sessionId) {
  const d = await srv.api('/hhttps/role/declare', { method: 'POST', body: { sessionId } });
  assert.equal(d.status, 200, d.text);
  return d.json.hhttps.token;
}

function assertGate(r) {
  assert.equal(r.status, 403, r.text);
  assert.equal(r.json?.error, 'email_verification_required', r.text);
}

// ═══════════════════════════════════════════════════════════════════════════
// Group 1 — /hhttps/email/send input validation (negative cases, no AK)
// ═══════════════════════════════════════════════════════════════════════════

test('N-1: /email/send with empty or missing email → 400 Invalid email address', { skip }, async () => {
  const sessionId = await newSession();
  for (const body of [{ sessionId, email: '' }, { sessionId }, { sessionId, email: '   ' }, { sessionId, email: null }]) {
    const r = await srv.api('/hhttps/email/send', { method: 'POST', body });
    assert.equal(r.status, 400, r.text);
    assert.equal(r.json.error, 'Invalid email address.');
  }
  assert.equal((await sql('SELECT 1 FROM email_verifications WHERE session_id = $1', [sessionId])).length, 0, 'no verification row');
});

test('N-2: /email/send with a malformed address → 400 (no verification row, no context)', { skip }, async () => {
  const sessionId = await newSession();
  for (const email of ['foo', 'a@b', 'a b@c.de', 'a@@b.de', '@c.de', 'a@c.']) {
    const r = await srv.api('/hhttps/email/send', { method: 'POST', body: { sessionId, email } });
    assert.equal(r.status, 400, `${email}: ${r.text}`);
    assert.equal(r.json.error, 'Invalid email address.');
  }
  assert.equal((await sql('SELECT 1 FROM email_verifications WHERE session_id = $1', [sessionId])).length, 0);
  assert.equal((await sql('SELECT 1 FROM challenges WHERE challenge_id = $1', [`email:${sessionId}`])).length, 0);
});

test('N-3: /email/send with an unknown session → 401 Invalid session', { skip }, async () => {
  const r = await srv.api('/hhttps/email/send', { method: 'POST', body: { sessionId: crypto.randomUUID(), email: freshEmail('n3') } });
  assert.equal(r.status, 401, r.text);
  assert.equal(r.json.error, 'Invalid session.');
});

test('N-4: more than 3 sends per session → 429 (4th send)', { skip }, async () => {
  const sessionId = await newSession();
  const email = freshEmail('n4');
  for (let i = 0; i < 3; i++) await send(sessionId, email);
  const r = await srv.api('/hhttps/email/send', { method: 'POST', body: { sessionId, email } });
  assert.equal(r.status, 429, r.text);
});

// ═══════════════════════════════════════════════════════════════════════════
// Group 2 — /hhttps/email/confirm-code boundaries (AK-23, AK-24) + negatives
// ═══════════════════════════════════════════════════════════════════════════

test('(harness) fresh server for group 2', { skip }, async () => { await restart(); });

test('AK-23: tab inside the code ("482\\t913") is accepted', { skip }, async () => {
  const sessionId = await newSession();
  const { devCode } = await send(sessionId, freshEmail('tab'));
  const r = await confirm(sessionId, devCode.slice(0, 3) + '\t' + devCode.slice(3));
  assert.equal(r.status, 200, r.text);
  assert.equal(r.json.verified, true);
  track.add({ userId: r.json.userId });
});

test('AK-23: hyphen inside the code ("482-913") is accepted', { skip }, async () => {
  const sessionId = await newSession();
  const { devCode } = await send(sessionId, freshEmail('dash'));
  const r = await confirm(sessionId, devCode.slice(0, 3) + '-' + devCode.slice(3));
  assert.equal(r.status, 200, r.text);
  assert.equal(r.json.verified, true);
  track.add({ userId: r.json.userId });
});

test('AK-24 / N-5: letters, 7 digits, symbols-only, empty code → 400; then the correct code still works; then reuse → 400', { skip }, async () => {
  const sessionId = await newSession();
  const email = freshEmail('n5');
  const { devCode } = await send(sessionId, email);

  const letters = await confirm(sessionId, devCode.slice(0, 5) + 'a');
  assert.equal(letters.status, 400, letters.text);
  assert.equal(letters.json.error, 'Code must be 6 digits.');

  const seven = await confirm(sessionId, devCode + '1');
  assert.equal(seven.status, 400, seven.text);

  const symbols = await confirm(sessionId, '--- ---');
  assert.equal(symbols.status, 400, symbols.text);

  const empty = await confirm(sessionId, '');
  assert.equal(empty.status, 400, empty.text);
  assert.equal(empty.json.error, 'sessionId and code required.');

  // the invalid attempts did not consume the code
  const ok = await confirm(sessionId, devCode);
  assert.equal(ok.status, 200, ok.text);
  track.add({ email, userId: ok.json.userId });

  // N-6: second use of the same code → 400, session unchanged
  const again = await confirm(sessionId, devCode);
  assert.equal(again.status, 400, again.text);
  assert.match(again.json.error, /already used/);
  const row = await sessionRow(sessionId);
  assert.equal(row.user_id, ok.json.userId);
  assert.equal(row.email_verified, true);
});

test('N-6b: a wrong-but-well-formed code (6 digits) → 400, code row stays open, correct code still works', { skip }, async () => {
  const sessionId = await newSession();
  const email = freshEmail('n6b');
  const { devCode } = await send(sessionId, email);
  const wrong = String((Number(devCode) + 1) % 1_000_000).padStart(6, '0');
  const r = await confirm(sessionId, wrong);
  assert.equal(r.status, 400, r.text);
  assert.match(r.json.error, /wrong, expired or already used/);
  const ok = await confirm(sessionId, devCode);
  assert.equal(ok.status, 200, ok.text);
  track.add({ email, userId: ok.json.userId });
});

test('N-7: confirm-code with an unknown session → 404 (session is checked before the code, #22); no anchor', { skip }, async () => {
  const r = await confirm(crypto.randomUUID(), '123456');
  assert.equal(r.status, 404, r.text);
  assert.match(r.json.error, /Session not found or expired/);
});

test('N-8: expired verification row (TTL elapsed) → 400, no bind', { skip }, async () => {
  const sessionId = await newSession();
  const email = freshEmail('n8');
  const { devCode } = await send(sessionId, email);
  await sql(`UPDATE email_verifications SET expires_at = NOW() - INTERVAL '1 minute' WHERE session_id = $1`, [sessionId]);
  const r = await confirm(sessionId, devCode);
  assert.equal(r.status, 400, r.text);
  assert.equal(await anchorCount(email), 0);
  assert.equal((await sessionRow(sessionId)).email_verified, false);
});

test('N-9: expired email context (challenge row) but valid code → 409 email_context_missing, no bind', { skip }, async () => {
  const sessionId = await newSession();
  const email = freshEmail('n9');
  const { devCode } = await send(sessionId, email);
  await sql(`UPDATE challenges SET expires_at = NOW() - INTERVAL '1 minute' WHERE challenge_id = $1`, [`email:${sessionId}`]);
  const r = await confirm(sessionId, devCode);
  assert.equal(r.status, 409, r.text);
  assert.equal(r.json.error, 'email_context_missing');
  assert.equal(await anchorCount(email), 0);
  assert.equal((await sessionRow(sessionId)).email_verified, false);
});

test('N-10: expired session with a valid code → 404; the code is NOT consumed (session is checked first, #22)', { skip }, async () => {
  const sessionId = await newSession();
  const email = freshEmail('n10');
  const { devCode } = await send(sessionId, email);
  await sql(`UPDATE sessions SET expires_at = NOW() - INTERVAL '1 minute' WHERE session_id = $1`, [sessionId]);
  const r = await confirm(sessionId, devCode);
  assert.equal(r.status, 404, r.text);
  assert.equal(await anchorCount(email), 0);
  const [v] = await sql('SELECT used FROM email_verifications WHERE session_id = $1', [sessionId]);
  assert.equal(v.used, false, 'the code row stays unused when the session is already gone');
});

// ═══════════════════════════════════════════════════════════════════════════
// Group 3 — pseudonym boundaries over HTTP (AK-6/7/8), AK-16 TTL, AK-1 hash
// ═══════════════════════════════════════════════════════════════════════════

test('(harness) fresh server for group 3', { skip }, async () => { await restart(); });

test('AK-6: pseudonym of 40 chars via /email/send → stored as its first 32 chars (anchor + session + cache)', { skip }, async () => {
  const email = freshEmail('p40');
  const long = 'P'.repeat(40);
  const { userId, pseudonym, sessionId } = await verifyEmail(srv, email, long, track);
  assert.equal(pseudonym, 'P'.repeat(32));
  const [a] = await sql('SELECT pseudonym FROM identity_anchors WHERE user_id = $1', [userId]);
  assert.equal(a.pseudonym, 'P'.repeat(32));
  assert.equal((await sessionRow(sessionId)).pseudonym, 'P'.repeat(32));
  const [c] = await sql('SELECT pseudonym FROM identity_claims_cache WHERE user_id = $1', [userId]);
  assert.equal(c.pseudonym, 'P'.repeat(32));
});

test('AK-6: exactly 32 allowed chars (umlauts, dot, dash, underscore, space) are kept unchanged', { skip }, async () => {
  const p = 'Änne Müller-Ö.ß_x'.padEnd(32, 'y');
  assert.equal(p.length, 32);
  const { pseudonym } = await verifiedSession('p32', p);
  assert.equal(pseudonym, p);
});

test('AK-7: pseudonym consisting only of forbidden chars → generated iamhmn_ pseudonym', { skip }, async () => {
  const { pseudonym } = await verifiedSession('psym', '!!!###');
  assert.match(pseudonym, /^iamhmn_[a-z0-9]{10}$/);
});

test('AK-6/AK-8: pseudonym wish from /session/start is used when /email/send carries none; a later different wish does not change it', { skip }, async () => {
  const email = freshEmail('wish');
  const s1 = await newSession({ pseudonym: 'Wish One' });
  const c1 = await confirm(s1, (await send(s1, email)).devCode);
  assert.equal(c1.status, 200, c1.text);
  track.add({ email, userId: c1.json.userId });
  assert.equal(c1.json.pseudonym, 'Wish One');

  const s2 = await newSession({ pseudonym: 'Wish Two' });
  const c2 = await confirm(s2, (await send(s2, email, { pseudonym: 'Wish Three' })).devCode);
  assert.equal(c2.status, 200, c2.text);
  assert.equal(c2.json.userId, c1.json.userId);
  assert.equal(c2.json.pseudonym, 'Wish One', 'AK-8: the anchor pseudonym wins');
  assert.equal((await sessionRow(s2)).pseudonym, 'Wish One');
});

test('AK-16: the claims cache row expires within 7 days of the confirmation', { skip }, async () => {
  const { userId } = await verifiedSession('ttl');
  const [c] = await sql(
    `SELECT (expires_at <= NOW() + INTERVAL '7 days') AS within, (expires_at > NOW() + INTERVAL '6 days') AS long_enough
       FROM identity_claims_cache WHERE user_id = $1`, [userId]);
  assert.equal(c.within, true, 'expires_at ≤ now + 7 days');
  assert.equal(c.long_enough, true, 'expires_at > now + 6 days (TTL is the documented 7 days)');
});

test('AK-1: the anchor key is HMAC-SHA256(pepper, normalize(E)) — no plaintext, no plain sha256', { skip }, async () => {
  const email = `ACC-Hash-${rnd()}@Example.ORG`;
  const { userId } = await verifyEmail(srv, email, undefined, track);
  const expected = crypto.createHmac('sha256', TEST_PEPPER).update(email.trim().toLowerCase()).digest('hex');
  const [a] = await sql('SELECT email_hash FROM identity_anchors WHERE user_id = $1', [userId]);
  assert.equal(a.email_hash, expected);
  const plainSha = crypto.createHash('sha256').update(email.toLowerCase()).digest('hex');
  assert.equal((await sql('SELECT 1 FROM identity_anchors WHERE email_hash = $1', [plainSha])).length, 0);
  assert.equal((await sql('SELECT 1 FROM identity_anchors WHERE email_hash = $1', [email.toLowerCase()])).length, 0);
});

// ═══════════════════════════════════════════════════════════════════════════
// Group 4 — gate negatives (AK-10..13), approve negatives, machine path,
//           AK-21 with a simulated passkey credential, AK-3 concurrency
// ═══════════════════════════════════════════════════════════════════════════

test('(harness) fresh server for group 4', { skip }, async () => { await restart(); });

test('AK-13: a session with a passkey credential but NO confirmed email → role/declare 403 (passkey alone no longer suffices)', { skip }, async () => {
  const sessionId = await newSession();
  const before = await sessionRow(sessionId);
  await attachSimulatedPasskey(sessionId, before.user_id);
  track.add({ userId: before.user_id });
  const r = await srv.api('/hhttps/role/declare', { method: 'POST', body: { sessionId } });
  assertGate(r);
  assert.equal(r.json.hhttps, undefined, 'no token');
});

test('AK-13: a session with github_verified but NO confirmed email → role/declare 403 (GitHub alone no longer suffices)', { skip }, async () => {
  const sessionId = await newSession();
  await sql('UPDATE sessions SET github_verified = TRUE, github_trust_bonus = 25 WHERE session_id = $1', [sessionId]);
  const r = await srv.api('/hhttps/role/declare', { method: 'POST', body: { sessionId } });
  assertGate(r);
});

test('AK-10/AK-11/AK-12/AK-13 with an unknown session → 404 / 401 / 404 / 401 (no gate answer, no token)', { skip }, async () => {
  const sid = crypto.randomUUID();
  const reg = await srv.api('/hhttps/webauthn/register/start', { method: 'POST', body: { sessionId: sid } });
  assert.equal(reg.status, 404, reg.text);

  const gh = await fetch(`${srv.baseUrl}/hhttps/verify/github/start?session=${sid}`, { redirect: 'manual' });
  assert.equal(gh.status, 401, await gh.text());

  const nonce = rnd(); const iat = Date.now();
  const assertion = crypto.createHmac('sha256', TEST_EUDI_SECRET)
    .update(JSON.stringify({ sessionId: sid, eidVerified: true, nonce, iat })).digest('hex');
  const eid = await srv.api('/hhttps/eid/upgrade', { method: 'POST', body: { sessionId: sid, nonce, iat, assertion } });
  assert.equal(eid.status, 404, eid.text);
  assert.equal(eid.json.hhttps, undefined);

  const rd = await srv.api('/hhttps/role/declare', { method: 'POST', body: { sessionId: sid } });
  assert.equal(rd.status, 401, rd.text);
});

test('AK-12: eid/upgrade without assertion → 400; with a wrong assertion on an email-verified session → 401, no token', { skip }, async () => {
  const { sessionId } = await verifiedSession('eidneg');
  const missing = await srv.api('/hhttps/eid/upgrade', { method: 'POST', body: { sessionId } });
  assert.equal(missing.status, 400, missing.text);
  const wrong = await srv.api('/hhttps/eid/upgrade', { method: 'POST', body: { sessionId, nonce: 'n', iat: Date.now(), assertion: 'deadbeef' } });
  assert.equal(wrong.status, 401, wrong.text);
  assert.equal(wrong.json.hhttps, undefined);
});

test('AK-19 (approve): scope without openid → 400; unknown client → 400; garbage token → 401', { skip }, async () => {
  const { sessionId } = await verifiedSession('appneg');
  const token = await declare(sessionId);
  const clientId = await createClient();
  const { challenge } = pkce();

  const noOpenid = await approve(token, clientId, 'email', challenge);
  assert.equal(noOpenid.status, 400, noOpenid.text);
  // AP2-33 (#175): RFC 6749 code + human text in error_description.
  assert.equal(noOpenid.json.error, 'invalid_scope');
  assert.match(noOpenid.json.error_description, /openid/);

  const unknownClient = await approve(token, 'does-not-exist', 'openid email', challenge);
  assert.equal(unknownClient.status, 400, unknownClient.text);

  const badToken = await approve('not.a.jwt', clientId, 'openid', challenge);
  assert.equal(badToken.status, 401, badToken.text);

  assert.equal((await sql('SELECT 1 FROM authorization_codes WHERE client_id = $1', [clientId])).length, 0, 'no code row');
});

/**
 * Machine operator seeded straight into machine_operators. /hhttps/machine/register
 * cannot be used here — it crashes the server process (see the B-1 todo test at
 * the end of this file), so the approve path is exercised with a seeded row.
 */
async function seedOperator(contactEmail) {
  const operatorId = 'op-acc-' + rnd();
  const apiKey = 'mk-' + crypto.randomBytes(24).toString('hex');
  const apiKeyHash = crypto.createHash('sha256').update(apiKey).digest('hex');
  await sql(
    `INSERT INTO machine_operators (operator_id, operator_name, purpose, contact_email, api_key_hash)
     VALUES ($1, 'ACC Bot', 'acceptance test', $2, $3)`,
    [operatorId, contactEmail, apiKeyHash]
  );
  operatorIds.add(operatorId);
  return { operatorId, apiKey };
}

test('Machine path: machine token → approve "openid email" → bot claims, NO email/pseudonym/flags for the platform', { skip }, async () => {
  const email = freshEmail('machine');
  await verifyEmail(srv, email, 'Operator', track); // the operator is also a verified human — must not leak through
  const { operatorId, apiKey } = await seedOperator(email);

  const mt = await srv.api('/hhttps/machine/token', { method: 'POST', body: { operatorId, apiKey } });
  assert.equal(mt.status, 200, mt.text);
  const md = decodeJwtPayload(mt.json.token);
  assert.equal(md.sub, 'machine');
  assert.equal(md.pseudonym, undefined, 'machine token carries no pseudonym');

  const clientId = await createClient();
  const { tokens } = await codeFlow(mt.json.token, clientId, 'openid email');
  for (const [name, p] of [['id_token', decodeJwtPayload(tokens.id_token)], ['access_token', decodeJwtPayload(tokens.access_token)]]) {
    assert.equal(p.actor_type, 'bot', `${name}: actor_type bot`);
    assert.equal(p.human, false, `${name}: human false`);
    assert.equal(p.email, undefined, `${name}: no operator email leaks to the platform`);
    assert.equal(p.email_verified, false, `${name}: email_verified false`);
    assert.equal(p.passkey_verified, false, name);
    assert.deepEqual(p.verified_methods, [], `${name}: verified_methods empty`);
    assert.equal(p.preferred_username, undefined, `${name}: no preferred_username`);
  }
  const u = await srv.api('/hhttps/oauth/userinfo', { headers: { authorization: `Bearer ${tokens.access_token}` } });
  assert.equal(u.status, 200, u.text);
  assert.equal(u.json.email, undefined, 'userinfo: no operator email');
  assert.equal(u.json.preferred_username, undefined, 'userinfo: no pseudonym');
  assert.deepEqual(u.json.verified_methods, [], 'userinfo: no verified methods');
  // observation (not required by the spec): /userinfo does not echo actor_type —
  // only the id_token / access_token carry `actor_type: 'bot', human: false`.
  assert.equal(u.json.actor_type, undefined);
  // the operator's session identity is NOT what the platform sees
  const [row] = await sql('SELECT user_id FROM authorization_codes WHERE client_id = $1', [clientId]);
  assert.match(row.user_id, /^machine:op-/);
});

test('AK-21 (simulated credential): HHTTPS token with verified_methods ⊇ [email, passkey] → passkey_verified true in id_token, access_token, userinfo', { skip }, async () => {
  const { sessionId, userId, pseudonym } = await verifiedSession('ak21');
  await attachSimulatedPasskey(sessionId, userId);

  const token = await declare(sessionId);
  const td = decodeJwtPayload(token);
  assert.ok(td.verified_methods.includes('passkey'), 'HHTTPS token lists passkey');
  assert.equal(td.passkey_verified, true);
  assert.equal(td.pseudonym, pseudonym);

  const clientId = await createClient();
  const { tokens } = await codeFlow(token, clientId, 'openid email');
  for (const p of [decodeJwtPayload(tokens.id_token), decodeJwtPayload(tokens.access_token)]) {
    assert.equal(p.passkey_verified, true);
    assert.equal(p.email_verified, true);
    assert.ok(p.verified_methods.includes('passkey') && p.verified_methods.includes('email'));
    assert.equal(p.preferred_username, pseudonym);
  }
  const u = await srv.api('/hhttps/oauth/userinfo', { headers: { authorization: `Bearer ${tokens.access_token}` } });
  assert.equal(u.status, 200, u.text);
  assert.equal(u.json.passkey_verified, true);
  assert.ok(u.json.verified_methods.includes('passkey'));
});

test('AK-3: two sessions ALIVE AT THE SAME TIME carry the same userId → same sub at the same client', { skip }, async () => {
  const email = freshEmail('ak3');
  const a = await verifyEmail(srv, email, undefined, track);
  const b = await verifyEmail(srv, ` ${email.toUpperCase()}`, undefined, track);
  assert.equal(a.userId, b.userId);
  const rows = await sql('SELECT session_id FROM sessions WHERE user_id = $1 AND expires_at > NOW()', [a.userId]);
  assert.deepEqual(rows.map(r => r.session_id).sort(), [a.sessionId, b.sessionId].sort(), 'both sessions are alive concurrently');

  const clientId = await createClient(['openid']);
  const ta = await declare(a.sessionId);
  const tb = await declare(b.sessionId);
  const ra = await codeFlow(ta, clientId, 'openid');
  const rb = await codeFlow(tb, clientId, 'openid');
  assert.equal(decodeJwtPayload(ra.tokens.id_token).sub, decodeJwtPayload(rb.tokens.id_token).sub);

  // different client → different sub (pairwise, unchanged algorithm)
  const other = await createClient(['openid']);
  const ro = await codeFlow(ta, other, 'openid');
  assert.notEqual(decodeJwtPayload(ro.tokens.id_token).sub, decodeJwtPayload(ra.tokens.id_token).sub);
});

// ═══════════════════════════════════════════════════════════════════════════
// AK-27 / AK-28 — email gate on the age endpoints (T8, decision 2026-09-12).
// ═══════════════════════════════════════════════════════════════════════════

test('AK-28: /hhttps/age/direct with a VALID assertion → 403 email_verification_required, no identity bootstrapped',
  { skip }, async () => {
  const nonce = rnd(); const iat = Date.now();
  const ageOver = { age_over_14: true, age_over_16: true, age_over_18: true };
  const canonical = JSON.stringify({ direct: true, ageOver, nonce, iat });
  const assertion = crypto.createHmac('sha256', TEST_EUDI_SECRET).update(canonical).digest('hex');
  const r = await srv.api('/hhttps/age/direct', { method: 'POST', body: { ageOver, assertion, nonce, iat } });
  if (r.json?.hhttps?.userId) track.add({ userId: r.json.hhttps.userId, sessionId: r.json.hhttps.sessionId });
  assert.equal(r.status, 403, `expected email gate, observed ${r.status}: ${r.text.slice(0, 200)}`);
  assert.equal(r.json.error, 'email_verification_required');
  assert.equal(r.json.hhttps, undefined, 'no hhttps block / token must be issued');
});

test('AK-27: /hhttps/age/upgrade on a session WITHOUT confirmed email → 403 email_verification_required, no token',
  { skip }, async () => {
  const sessionId = await newSession();
  const nonce = rnd(); const iat = Date.now();
  const ageOver = { age_over_14: true, age_over_16: true, age_over_18: true };
  const canonical = JSON.stringify({ sessionId, ageOver, nonce, iat });
  const assertion = crypto.createHmac('sha256', TEST_EUDI_SECRET).update(canonical).digest('hex');
  const r = await srv.api('/hhttps/age/upgrade', { method: 'POST', body: { sessionId, ageOver, assertion, nonce, iat } });
  assert.equal(r.status, 403, `expected email gate, observed ${r.status}: ${r.text.slice(0, 200)}`);
  assert.equal(r.json.error, 'email_verification_required');
  assert.equal(r.json.hhttps, undefined, 'no hhttps block / token must be issued');
});

test('AK-28: /hhttps/age/direct never issues an hhttps.token (age-only identity without pseudonym is impossible)',
  { skip }, async () => {
  const nonce = rnd(); const iat = Date.now();
  const ageOver = { age_over_18: true };
  const canonical = JSON.stringify({ direct: true, ageOver: { age_over_14: false, age_over_16: false, age_over_18: true }, nonce, iat });
  const assertion = crypto.createHmac('sha256', TEST_EUDI_SECRET).update(canonical).digest('hex');
  const r = await srv.api('/hhttps/age/direct', { method: 'POST', body: { ageOver, assertion, nonce, iat } });
  if (r.json?.hhttps?.userId) track.add({ userId: r.json.hhttps.userId, sessionId: r.json.hhttps.sessionId });
  assert.equal(r.status, 403, r.text);
  assert.equal(r.json?.hhttps?.token, undefined, `no token expected; observed ${r.text.slice(0, 200)}`);
  assert.equal(r.json?.hhttps?.refreshToken, undefined, 'no refresh token expected');
});

// ═══════════════════════════════════════════════════════════════════════════
// #7 (formerly B-1) — /hhttps/machine/register used to kill the server process
// (unhandled rejection: column machine_operators.key_jkt missing, route without
// try/catch). Runs LAST on its own server instance so a regression cannot
// poison the other groups.
// ═══════════════════════════════════════════════════════════════════════════

test('#7: POST /hhttps/machine/register on an email-verified session → 201 with operatorId/apiKey, server keeps running',
  { skip }, async () => {
  await restart();
  const email = freshEmail('b1');
  const { sessionId } = await verifyEmail(srv, email, 'Operator', track);
  let status = null; let text = ''; let json = null;
  try {
    const reg = await srv.api('/hhttps/machine/register', {
      method: 'POST', body: { operatorName: 'ACC Bot', purpose: 'acceptance test', contactEmail: email, sessionId }
    });
    status = reg.status; text = reg.text; json = reg.json;
    if (reg.json?.operatorId) operatorIds.add(reg.json.operatorId);
  } catch (e) {
    text = `fetch failed (${e.message}); server log: ${srv.logs().split('\n').filter(l => /Query failed|does not exist|UNHANDLED/.test(l)).join(' | ')}`;
  }
  // The server must still be alive after the call — the crash was the bug.
  let info;
  try {
    info = await srv.api('/hhttps/info');
  } catch (e) {
    info = { status: null, text: `fetch failed (${e.message}) — server process died` };
  } finally {
    // whatever happened, leave a live server behind for test.after()
    await restart();
  }
  assert.equal(status, 201, text);
  assert.match(String(json?.operatorId), /^op-[0-9a-f]{16}$/, text);
  assert.match(String(json?.apiKey), /^mk-[0-9a-f]{48}$/, text);
  assert.equal(info.status, 200, `server must keep running after /machine/register; observed ${info.status}: ${info.text}`);
});
