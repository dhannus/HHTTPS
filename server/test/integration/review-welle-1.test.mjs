// Review 2026-09, Welle 1 — integration tests against a booted server.js:
//   AP5-01 / AP4-01  refresh tokens are not bearer credentials; validate/protected reflect the actor
//   AP4-03           /hhttps/revoke ends the holder's refresh chain
//   AP2-01           /hhttps/oauth/revoke ends the platform's OAuth refresh chain
//   AP4-02 / AP4-20  age/upgrade issues the full surface, age survives token/refresh,
//                    a foreign currentToken cannot transplant claims
//   AP4-21           documentProvided never unlocks a protected profession
//   AP5-17           plugin registration is rate-limited per req.ip
//   AP5-02 / AP2-23  DB-level: confirmEmail reports the state change; expired auth codes are cleaned
//   AP6-01           a fresh database migrated by scripts/migrate.js satisfies the boot checks
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import { startServer, pgAvailable } from '../helpers/server.mjs';
import { closeDb, sql, TEST_DB, TEST_EUDI_SECRET } from '../helpers/db.mjs';
import { rnd, freshEmail, verifyEmail, decodeJwtPayload, createTracker } from '../helpers/identity-flow.mjs';
import { migrate, MIGRATION_ORDER } from '../../scripts/migrate.js';

const skip = !pgAvailable() && 'TEST_PG_HOST not set';
const REDIRECT_URI = 'http://localhost/cb';
let srv;
const track = createTracker();
const clientIds = new Set();

test.before(async () => {
  if (skip) return;
  srv = await startServer({ env: { SMTP_HOST: '', SMTP_USER: '', SMTP_PASS: '', GITHUB_CLIENT_ID: '', GITHUB_CLIENT_SECRET: '' } });
});
test.after(async () => {
  if (skip) return;
  const ids = [...clientIds];
  if (ids.length) {
    await sql('DELETE FROM refresh_tokens WHERE client_id = ANY($1)', [ids]);
    await sql('DELETE FROM authorization_codes WHERE client_id = ANY($1)', [ids]);
    await sql('DELETE FROM connected_platforms WHERE client_id = ANY($1)', [ids]);
    await sql('DELETE FROM oauth_clients WHERE client_id = ANY($1)', [ids]);
  }
  await track.cleanup();
  await srv.stop();
  await closeDb();
});

const auth = (token) => ({ headers: { authorization: `Bearer ${token}` } });
const hmac = (canonical) => crypto.createHmac('sha256', TEST_EUDI_SECRET).update(canonical).digest('hex');
const ageAssertion = (sessionId, nonce, iat) => hmac(JSON.stringify({ sessionId,
  ageOver: { age_over_14: true, age_over_16: true, age_over_18: true }, nonce, iat }));
const eidAssertion = (sessionId, nonce, iat) => hmac(JSON.stringify({ sessionId, eidVerified: true, nonce, iat }));

/** e-mail-verified session → { sessionId, userId, token, refreshToken }. */
async function signedIn(tag) {
  const { sessionId, userId, pseudonym } = await verifyEmail(srv, freshEmail(tag), undefined, track);
  const r = await srv.api('/hhttps/role/declare', { method: 'POST', body: { sessionId } });
  assert.equal(r.status, 200, r.text);
  return { sessionId, userId, pseudonym, token: r.json.hhttps.token, refreshToken: r.json.hhttps.refreshToken };
}

async function createClient(allowedScopes = ['openid', 'role', 'email']) {
  const clientId = `test-w1-${rnd()}`;
  await sql(
    `INSERT INTO oauth_clients
       (client_id, client_secret_hash, name, homepage_url, redirect_uris, allowed_scopes,
        subject_type, verified, is_active, verification_status)
     VALUES ($1, NULL, $2, $3, $4, $5, 'pairwise', TRUE, TRUE, 'verified')`,
    [clientId, `W1 test client ${clientId}`, 'http://localhost', JSON.stringify([REDIRECT_URI]), JSON.stringify(allowedScopes)]
  );
  clientIds.add(clientId);
  return clientId;
}

async function codeFlow(token, clientId, scope = 'openid email') {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const a = await srv.api('/hhttps/oauth/approve', { method: 'POST',
    body: { token, client_id: clientId, redirect_uri: REDIRECT_URI, scope, code_challenge: challenge, code_challenge_method: 'S256' } });
  assert.equal(a.status, 200, a.text);
  const code = new URL(a.json.redirect).searchParams.get('code');
  const t = await srv.api('/hhttps/oauth/token', { method: 'POST',
    body: { grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI, client_id: clientId, code_verifier: verifier } });
  assert.equal(t.status, 200, t.text);
  return t.json;
}

// ─── AP5-01 / AP4-01 ─────────────────────────────────────────────────────────
test('AP5-01: a refresh token is refused as bearer credential (whoami, validate, protected)', { skip }, async () => {
  const { refreshToken, token } = await signedIn('w1a');
  assert.equal(decodeJwtPayload(refreshToken).sub, 'refresh');
  assert.equal((await srv.api('/hhttps/whoami', auth(refreshToken))).status, 401);
  assert.equal((await srv.api('/hhttps/validate', { method: 'POST', body: { token: refreshToken } })).status, 401);
  assert.equal((await srv.api('/hhttps/protected', auth(refreshToken))).status, 401);
  // the access token still works everywhere
  const v = await srv.api('/hhttps/validate', { method: 'POST', body: { token } });
  assert.equal(v.status, 200, v.text);
  assert.equal(v.json.hhttps.human, true);
  assert.equal(v.json.hhttps.actorType, 'human');
  assert.equal((await srv.api('/hhttps/protected', auth(token))).status, 200);
  // and the refresh token still refreshes
  const rf = await srv.api('/hhttps/token/refresh', { method: 'POST', body: { refreshToken } });
  assert.equal(rf.status, 200, rf.text);
});

// ─── AP4-03 ──────────────────────────────────────────────────────────────────
test('AP4-03: /hhttps/revoke ends the refresh chain of the holder', { skip }, async () => {
  const { token, refreshToken } = await signedIn('w1b');
  const rv = await srv.api('/hhttps/revoke', { method: 'POST', body: { token } });
  assert.equal(rv.status, 200, rv.text);
  const rf = await srv.api('/hhttps/token/refresh', { method: 'POST', body: { refreshToken } });
  assert.equal(rf.status, 401, `refresh after revoke must fail: ${rf.text}`);
  assert.equal((await srv.api('/hhttps/validate', { method: 'POST', body: { token } })).status, 401);
});

// ─── AP2-01 ──────────────────────────────────────────────────────────────────
test('AP2-01: disconnecting a platform ends its OAuth refresh chain (refresh grant → invalid_grant)', { skip }, async () => {
  const { token } = await signedIn('w1c');
  const clientId = await createClient();
  const tokens = await codeFlow(token, clientId);
  assert.ok(tokens.refresh_token, 'refresh_token issued');
  // sanity: the chain works before the disconnect
  const ok = await srv.api('/hhttps/oauth/token', { method: 'POST',
    body: { grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: clientId } });
  assert.equal(ok.status, 200, ok.text);
  const rv = await srv.api('/hhttps/oauth/revoke', { method: 'POST', body: { token, client_id: clientId } });
  assert.equal(rv.status, 200, rv.text);
  assert.ok(rv.json.refresh_tokens_revoked >= 1, 'the platform chain was revoked');
  const rf = await srv.api('/hhttps/oauth/token', { method: 'POST',
    body: { grant_type: 'refresh_token', refresh_token: ok.json.refresh_token, client_id: clientId } });
  assert.equal(rf.status, 400, rf.text);
  assert.equal(rf.json.error, 'invalid_grant');
});

// ─── AP4-02 / AP4-20 ─────────────────────────────────────────────────────────
test('AP4-02: age/upgrade issues the full surface; verified age survives token/refresh', { skip }, async () => {
  const { sessionId, userId, pseudonym } = await signedIn('w1d');
  const nonce = rnd(); const iat = Date.now();
  const r = await srv.api('/hhttps/age/upgrade', { method: 'POST',
    body: { sessionId, nonce, iat, ageOver: { age_over_14: true, age_over_16: true, age_over_18: true }, assertion: ageAssertion(sessionId, nonce, iat) } });
  assert.equal(r.status, 200, r.text);
  const p = decodeJwtPayload(r.json.hhttps.token);
  assert.equal(p.userId, userId);
  assert.equal(p.pseudonym, pseudonym, 'pseudonym present (was missing before AP4-02)');
  assert.equal(p.email_verified, true, 'method flags present');
  assert.equal(p.age_verified, true);
  assert.ok(p.age_group, 'age_group set');
  const rf = await srv.api('/hhttps/token/refresh', { method: 'POST', body: { refreshToken: r.json.hhttps.refreshToken } });
  assert.equal(rf.status, 200, rf.text);
  const q = decodeJwtPayload(rf.json.token);
  assert.equal(q.age_group, p.age_group, 'age_group survives the refresh');
  assert.equal(q.age_verified, true);
  assert.equal(q.pseudonym, pseudonym);
});

test('AP4-20: a currentToken of another user cannot transplant eudi_verified into age/upgrade', { skip }, async () => {
  // user B gets an eID-verified token
  const b = await signedIn('w1e-b');
  const nb = rnd(); const ib = Date.now();
  const eb = await srv.api('/hhttps/eid/upgrade', { method: 'POST', body: { sessionId: b.sessionId, nonce: nb, iat: ib, assertion: eidAssertion(b.sessionId, nb, ib) } });
  assert.equal(eb.status, 200, eb.text);
  assert.equal(decodeJwtPayload(eb.json.hhttps.token).eudi_verified, true);
  // user A presents B's token as currentToken
  const a = await signedIn('w1e-a');
  const na = rnd(); const ia = Date.now();
  const ra = await srv.api('/hhttps/age/upgrade', { method: 'POST',
    body: { sessionId: a.sessionId, nonce: na, iat: ia, currentToken: eb.json.hhttps.token,
            ageOver: { age_over_14: true, age_over_16: true, age_over_18: true }, assertion: ageAssertion(a.sessionId, na, ia) } });
  assert.equal(ra.status, 200, ra.text);
  const pa = decodeJwtPayload(ra.json.hhttps.token);
  assert.equal(pa.userId, a.userId);
  assert.notEqual(pa.eudi_verified, true, 'foreign eudi claim was not transplanted');
  assert.ok(!(pa.verified_methods || []).includes('eudi'));
});

// ─── AP4-21 ──────────────────────────────────────────────────────────────────
test('AP4-21: documentProvided:true does not unlock a protected profession', { skip }, async () => {
  const { sessionId } = await signedIn('w1f');
  const r = await srv.api('/hhttps/role/card', { method: 'POST',
    body: { sessionId, documentProvided: true, esco: { label: 'Rechtsanwalt', isco08: '2611' } } });
  assert.equal(r.status, 400, r.text);
  assert.equal(r.json.reason, 'reserved');
  assert.match(r.json.remedy, /RAL2/);
  assert.doesNotMatch(r.text, /document-checked/);
});

// ─── AP5-17 ──────────────────────────────────────────────────────────────────
test('AP5-17: plugin registration is limited to 5 per hour per req.ip', { skip }, async () => {
  // The limiter keys on req.ip (Express `trust proxy 1` → the address nginx
  // appends, not a client-supplied one). The harness talks to the server
  // directly, so every request here comes from 127.0.0.1.
  const statuses = [];
  for (let i = 0; i < 6; i++) {
    const r = await srv.api('/hhttps/plugin/register', { method: 'POST', body: {} });
    statuses.push(r.status);
  }
  assert.deepEqual(statuses.slice(0, 5).every(s => s === 400), true, `first five are validation errors: ${statuses}`);
  assert.equal(statuses[5], 429, `sixth is rate-limited: ${statuses}`);
});

// ─── AP5-02 / AP2-23 (DB level) ──────────────────────────────────────────────
test('AP5-02: confirmEmail reports whether a row changed; a second click confirms nothing', { skip }, async () => {
  process.env.DB_HOST = TEST_DB.host; process.env.DB_NAME = TEST_DB.database;
  process.env.DB_USER = TEST_DB.user; process.env.DB_PASSWORD = TEST_DB.password;
  const db = await import('../../db.js');
  const clientId = `test-w1-mail-${rnd()}`;
  await sql(`INSERT INTO oauth_clients (client_id, name, homepage_url, redirect_uris, allowed_scopes, verified, is_active, verification_status)
             VALUES ($1, 'x', 'https://example.org', '[]', '[]', TRUE, TRUE, 'verified')`, [clientId]);
  clientIds.add(clientId);
  await db.oauthClients.updateContactEmail(clientId, 'a@example.org', false, 'tok-' + rnd(), new Date(Date.now() + 3600_000));
  const [row] = await sql(`SELECT verified, verification_status FROM oauth_clients WHERE client_id = $1`, [clientId]);
  assert.equal(row.verified, false, 'verified flag is reset on e-mail change');
  assert.equal(row.verification_status, 'email_pending', 'always email_pending, never the dead "unverified"');
  assert.equal(await db.oauthClients.confirmEmail(clientId), true);
  assert.equal(await db.oauthClients.confirmEmail(clientId), false, 'nothing to confirm the second time');
});

test('AP2-23 / AP6-02: cleanupExpired removes expired authorization codes', { skip }, async () => {
  const db = await import('../../db.js');
  const clientId = await createClient();   // FK: authorization_codes.client_id → oauth_clients
  const code = 'c-' + rnd();
  await sql(`INSERT INTO authorization_codes (code, client_id, user_id, redirect_uri, scopes, role, trust_score, expires_at)
             VALUES ($1, $2, 'u', 'http://localhost/cb', '[]', 'citizen', 0, NOW() - INTERVAL '2 hours')`, [code, clientId]);
  const r = await db.cleanupExpired();
  assert.ok(r.deleted_auth_codes >= 1, `deleted_auth_codes counted: ${JSON.stringify(r)}`);
  assert.equal((await sql(`SELECT 1 FROM authorization_codes WHERE code = $1`, [code])).length, 0);
});

// ─── AP6-01 ──────────────────────────────────────────────────────────────────
test('AP6-01: a fresh database migrated by scripts/migrate.js has everything the boot checks need', { skip }, async () => {
  const dbName = `hhttps_fresh_${rnd()}`;
  try { await sql(`CREATE DATABASE ${dbName}`); }
  catch (e) { if (/permission/i.test(e.message)) return; throw e; }
  const client = new pg.Client({ ...TEST_DB, database: dbName });
  try {
    await client.connect();
    const first = await migrate({ client, log: { log() {} } });
    // The registry (db.js: MIGRATIONS) is the single source of the chain —
    // AP6-40 (#160). Asserting against it instead of a hard-coded count keeps
    // this test from failing every time a phase is added.
    assert.equal(first.applied.length, MIGRATION_ORDER.length,
      `all ${MIGRATION_ORDER.length} registered files applied on a fresh DB`);
    const again = await migrate({ client, log: { log() {} } });
    assert.equal(again.applied.length, 0, 'idempotent: nothing applied the second time');
    const cols = async (t, c) => (await client.query(
      `SELECT 1 FROM information_schema.columns WHERE table_name = $1 AND column_name = $2`, [t, c])).rowCount === 1;
    assert.ok(await cols('authorization_codes', 'verified_methods'), 'phase 8 boot check (authorization_codes.verified_methods)');
    assert.ok(await cols('machine_operators', 'key_jkt'), 'phase 4b');
    assert.ok(await cols('webhooks', 'owner_user_id'), 'phase 9');
    assert.ok(await cols('refresh_tokens', 'client_id'), 'phase 9');
    const t = await client.query(`SELECT data_type FROM information_schema.columns WHERE table_name='authorization_codes' AND column_name='state'`);
    assert.equal(t.rows[0].data_type, 'text', 'phase 3a1');
    assert.equal((await client.query(`SELECT to_regclass('identity_claims_cache') AS r`)).rows[0].r, 'identity_claims_cache');
  } finally {
    await client.end().catch(() => {});
    await sql(`DROP DATABASE IF EXISTS ${dbName}`);
  }
});
