// Review 2026-09, Welle 2 — AP4 integration tests against a booted server.js.
//
//   AP4-31  ageGroup is validated with an own-property check (prototype keys out)
//   AP4-05  a handler error answers instead of hanging; ?jti=a&jti=b is refused
//   AP4-04  /hhttps/revoke differentiates its error paths
//   AP4-25  a token with a broken signature never reaches the database
//   AP4-40  revoked_tokens is pruned instead of growing forever
//   AP4-27  the internal verifier endpoints require a fresh, single-use nonce
//   AP4-06  /hhttps/role/card enforces the same e-mail gate as /role/declare
//   AP4-07  documentProvided is a strict boolean; `human` mirrors the real surface
//   AP4-29  the issued iamhmn-card carries no userId
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { startServer, pgAvailable } from '../helpers/server.mjs';
import { closeDb, sql, TEST_EUDI_SECRET } from '../helpers/db.mjs';
import { rnd, freshEmail, verifyEmail, newSession, createTracker } from '../helpers/identity-flow.mjs';
import { startEudiploStub } from '../helpers/eudiplo-stub.mjs';

const skip = !pgAvailable() && 'TEST_PG_HOST not set';
let srv, eudiplo;
const track = createTracker();

test.before(async () => {
  if (skip) return;
  eudiplo = await startEudiploStub();
  srv = await startServer({ env: {
    SMTP_HOST: '', SMTP_USER: '', SMTP_PASS: '', GITHUB_CLIENT_ID: '', GITHUB_CLIENT_SECRET: '',
    EUDIPLO_BASE_URL: eudiplo.url, EUDIPLO_CLIENT_SECRET: 'stub-secret',
  } });
});
test.after(async () => {
  if (skip) return;
  await track.cleanup();
  await srv.stop();
  await eudiplo.stop();
  await closeDb();
});

const hmac = (canonical) => crypto.createHmac('sha256', TEST_EUDI_SECRET).update(canonical).digest('hex');
const ageAssertion = (sessionId, nonce, iat) => hmac(JSON.stringify({ sessionId,
  ageOver: { age_over_14: true, age_over_16: true, age_over_18: true }, nonce, iat }));
const AGE_OVER = { age_over_14: true, age_over_16: true, age_over_18: true };

async function signedIn(tag) {
  const { sessionId, userId } = await verifyEmail(srv, freshEmail(tag), undefined, track);
  const r = await srv.api('/hhttps/role/declare', { method: 'POST', body: { sessionId } });
  assert.equal(r.status, 200, r.text);
  return { sessionId, userId, token: r.json.hhttps.token, refreshToken: r.json.hhttps.refreshToken };
}

// ─── AP4-31 / AP4-05 ─────────────────────────────────────────────────────────
test('AP4-31: a prototype key as ageGroup is refused — and the handler answers', { skip }, async () => {
  const { sessionId, userId } = await verifyEmail(srv, freshEmail('w2-31'), undefined, track);
  for (const bad of ['constructor', '__proto__', 'toString', 'hasOwnProperty']) {
    const r = await srv.api('/hhttps/role/declare', { method: 'POST', body: { sessionId, ageGroup: bad } });
    assert.equal(r.status, 400, `${bad} → 400, got ${r.status} ${r.text}`);
    assert.match(r.json.error, /Unknown age group/);
  }
  // Non-string values are refused the same way (no lookup on a number/object).
  const obj = await srv.api('/hhttps/role/declare', { method: 'POST', body: { sessionId, ageGroup: { id: 'adult' } } });
  assert.equal(obj.status, 400, obj.text);
  // AP4-31 regression: no token may be issued before the crash.
  const rows = await sql('SELECT 1 FROM tokens WHERE user_id = $1', [userId]);
  assert.equal(rows.length, 0, 'no access token was issued for a rejected age group');
  // A real age group still works.
  const ok = await srv.api('/hhttps/role/declare', { method: 'POST', body: { sessionId, ageGroup: 'adult_18_plus' } });
  assert.equal(ok.status, 200, ok.text);
});

test('AP4-05: /hhttps/revoke/status refuses a repeated jti parameter instead of crashing', { skip }, async () => {
  const dup = await srv.api('/hhttps/revoke/status?jti=a&jti=b');
  assert.equal(dup.status, 400, dup.text);
  assert.equal(dup.json.error, 'jti required');
  const one = await srv.api(`/hhttps/revoke/status?jti=${crypto.randomUUID()}`);
  assert.equal(one.status, 200, one.text);
  assert.equal(one.json.revoked, false);
});

// ─── AP4-04 / AP4-25 / AP4-40 ────────────────────────────────────────────────
test('AP4-25: a token with a forged signature is rejected WITHOUT any database write', { skip }, async () => {
  const jti = crypto.randomUUID();
  const header = Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({ jti, role: 'citizen', userId: 'attacker' })).toString('base64url');
  const forged = `${header}.${payload}.${Buffer.from('nope').toString('base64url')}`;

  const r = await srv.api('/hhttps/revoke', { method: 'POST', body: { token: forged } });
  assert.equal(r.status, 401, r.text);
  const rows = await sql('SELECT 1 FROM revoked_tokens WHERE jti = $1', [jti]);
  assert.equal(rows.length, 0, 'the unverified payload never reached revoked_tokens');
  const st = await srv.api(`/hhttps/revoke/status?jti=${jti}`);
  assert.equal(st.json.revoked, false, 'and the oracle does not report it as revoked');
});

test('AP4-04: a non-UUID jti is refused with 400; a live token revokes with 200', { skip }, async () => {
  const bad = await srv.api('/hhttps/revoke', { method: 'POST', body: { token: 'not-a-jwt' } });
  assert.equal(bad.status, 401, bad.text);
  const empty = await srv.api('/hhttps/revoke', { method: 'POST', body: { token: 42 } });
  assert.equal(empty.status, 400, empty.text);

  const { token } = await signedIn('w2-04');
  const ok = await srv.api('/hhttps/revoke', { method: 'POST', body: { token } });
  assert.equal(ok.status, 200, ok.text);
  assert.equal(ok.json.revoked, true);
  const st = await srv.api(`/hhttps/revoke/status?jti=${ok.json.jti}`);
  assert.equal(st.json.revoked, true);
});

test('AP4-40: revoking prunes ban-list rows that are older than the longest token TTL', { skip }, async () => {
  const stale = `stale-${rnd()}`;
  await sql(`INSERT INTO revoked_tokens (jti, role, revoked_at, reason)
             VALUES ($1, 'citizen', NOW() - INTERVAL '90 days', 'test')`, [stale]);
  const { token } = await signedIn('w2-40');
  const ok = await srv.api('/hhttps/revoke', { method: 'POST', body: { token } });
  assert.equal(ok.status, 200, ok.text);
  assert.equal((await sql('SELECT 1 FROM revoked_tokens WHERE jti = $1', [stale])).length, 0,
    'the 90-day-old row was pruned (revoked_tokens used to be a permanent list)');
  assert.equal((await sql('SELECT 1 FROM revoked_tokens WHERE jti = $1', [ok.json.jti])).length, 1,
    'the fresh revocation is kept');
});

// ─── AP4-27 ──────────────────────────────────────────────────────────────────
test('AP4-27: the internal age upgrade needs a fresh, single-use nonce and a mandatory iat', { skip }, async () => {
  const { sessionId } = await verifyEmail(srv, freshEmail('w2-27'), undefined, track);
  const nonce = rnd(); const iat = Date.now();
  const body = { sessionId, ageOver: AGE_OVER, nonce, iat, assertion: ageAssertion(sessionId, nonce, iat) };

  // A genuinely internal call: loopback peer AND no X-Forwarded-For (the
  // proxied variant is covered by the separate AP4-27 test at the end).
  const first = await srv.api('/hhttps/age/upgrade', { method: 'POST', body });
  assert.equal(first.status, 200, first.text);

  const replay = await srv.api('/hhttps/age/upgrade', { method: 'POST', body });
  assert.equal(replay.status, 401, replay.text);
  assert.match(replay.json.error, /replay/i);

  const noNonce = await srv.api('/hhttps/age/upgrade', { method: 'POST',
    body: { sessionId, ageOver: AGE_OVER, iat, assertion: ageAssertion(sessionId, null, iat) } });
  assert.equal(noNonce.status, 401, noNonce.text);
  assert.match(noNonce.json.error, /nonce/i);

  const n2 = rnd();
  const noIat = await srv.api('/hhttps/age/upgrade', { method: 'POST',
    body: { sessionId, ageOver: AGE_OVER, nonce: n2, assertion: ageAssertion(sessionId, n2, null) } });
  assert.equal(noIat.status, 401, noIat.text);
  assert.match(noIat.json.error, /iat/i);
});

// ─── AP4-06 ──────────────────────────────────────────────────────────────────
test('AP4-06: /hhttps/role/card requires the confirmed e-mail, like /hhttps/role/declare', { skip }, async () => {
  const sessionId = await newSession(srv, {}, track);
  // A session that is verified via GitHub but has no confirmed e-mail: the old
  // ||-chain let it through, the e-mail gate does not.
  await sql('UPDATE sessions SET github_verified = TRUE WHERE session_id = $1', [sessionId]);
  const r = await srv.api('/hhttps/role/card', { method: 'POST',
    body: { sessionId, customRole: 'Gärtnerin' } });
  assert.equal(r.status, 403, r.text);
  assert.equal(r.json.error, 'email_verification_required');
  assert.equal(eudiplo.state.issuerOffers.length, 0, 'nothing was issued upstream');
});

// ─── AP4-07 / AP4-29 ─────────────────────────────────────────────────────────
test('AP4-07/AP4-29: documentProvided is strict, `human` mirrors the surface, the card has no userId', { skip }, async () => {
  const { sessionId, userId } = await verifyEmail(srv, freshEmail('w2-07'), undefined, track);
  eudiplo.state.issuerOffers.length = 0;

  // "false" is a string — truthy in JS, but not a document.
  const r = await srv.api('/hhttps/role/card', { method: 'POST',
    body: { sessionId, documentProvided: 'false', esco: { label: 'Gärtnerin', isco08: '6113' } } });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.json.card.ral, 0, 'a truthy non-boolean never lifts the RAL');
  assert.match(r.json.card.note, /Self-declared/);

  assert.equal(eudiplo.state.issuerOffers.length, 1, 'one card offer was issued');
  const claims = Object.values(eudiplo.state.issuerOffers[0].claims)[0].claims;
  assert.equal(claims.method, 'self-declared', `method stayed self-declared: ${JSON.stringify(claims)}`);
  assert.equal(claims.userId, undefined, 'AP4-29: the stable account key is not a card claim');
  assert.ok(!JSON.stringify(claims).includes(userId), 'the userId appears nowhere in the card');
  assert.equal(claims.human, 'true',
    'AP4-07: an e-mail-verified session is human, even without a passkey');
});

// AP4-27 follow-up (Welle-2-Zusammenführung): a loopback peer alone does not
// prove an internal caller — nginx sits on the same host. A request that
// carries X-Forwarded-For came through the proxy and is refused.
test('AP4-27: an X-Forwarded-For header marks the caller as external (403)', { skip }, async () => {
  for (const path of ['/hhttps/age/upgrade', '/hhttps/age/direct', '/hhttps/eid/upgrade']) {
    const r = await srv.api(path, {
      method: 'POST',
      headers: { 'x-forwarded-for': '203.0.113.7' },
      body: { sessionId: 'x', nonce: 'n', iat: Date.now(), assertion: 'a',
              ageOver: { age_over_18: true } }
    });
    assert.equal(r.status, 403, `${path}: ${r.text}`);
    assert.equal(r.json?.error, 'internal_endpoint');
  }
});
