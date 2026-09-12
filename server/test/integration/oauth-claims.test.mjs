// T6 / AK-3, AK-17, AK-18, AK-19, AK-20, AK-21: the OAuth/OIDC surface hands
// email (scope `email`), the account pseudonym (`preferred_username`), the
// verified methods and the four *_verified flags to platforms. Runs server.js
// as a child process (HTTP) and asserts against the same Postgres via SQL.
//
// AK-21 (passkey_verified: true end-to-end) cannot be exercised over HTTP
// without a real authenticator. The flags are derived in /hhttps/oauth/approve
// from `verified_methods` of the SIGNED HHTTPS token (D5: the token is the
// source of truth, not the cache) and carried through the code row into the
// ID/access token. The runs below use verified_methods = ['email'] and assert
// passkey_verified === false through the same path; the derivation itself
// (methodFlags) is covered by test/unit/identity.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { startServer, pgAvailable } from '../helpers/server.mjs';
import { sql, closeDb } from '../helpers/db.mjs';
import { rnd, freshEmail as mkEmail, verifyEmail, decodeJwtPayload, createTracker } from '../helpers/identity-flow.mjs';

const skip = !pgAvailable() && 'TEST_PG_HOST not set';
const REDIRECT_URI = 'http://localhost/cb';

const freshEmail = () => mkEmail('t6');

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
    await sql('DELETE FROM authorization_codes WHERE client_id = ANY($1)', [ids]);
    await sql('DELETE FROM connected_platforms WHERE client_id = ANY($1)', [ids]);
    await sql('DELETE FROM oauth_clients WHERE client_id = ANY($1)', [ids]);
  }
  await track.cleanup();
  await srv.stop();
  await closeDb();
});

// ─── helpers ────────────────────────────────────────────────────────────────

/** Public (PKCE) test client written straight into oauth_clients. */
async function createClient(allowedScopes = ['openid', 'role', 'email']) {
  const clientId = `test-t6-${rnd()}`;
  await sql(
    `INSERT INTO oauth_clients
       (client_id, client_secret_hash, name, homepage_url, redirect_uris, allowed_scopes,
        subject_type, verified, is_active, verification_status)
     VALUES ($1, NULL, $2, $3, $4, $5, 'pairwise', TRUE, TRUE, 'verified')`,
    [clientId, `T6 test client ${clientId}`, 'http://localhost', JSON.stringify([REDIRECT_URI]), JSON.stringify(allowedScopes)]
  );
  clientIds.add(clientId);
  return clientId;
}

function pkce() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

/** Email flow + role/declare → { token (HHTTPS access token), userId, pseudonym }. */
async function hhttpsToken(email, extra = {}) {
  const { sessionId, userId, pseudonym } = await verifyEmail(srv, email, extra.pseudonym, track);
  const d = await srv.api('/hhttps/role/declare', { method: 'POST', body: { sessionId } });
  assert.equal(d.status, 200, d.text);
  return { token: d.json.hhttps.token, userId, pseudonym };
}

/** approve → code → token exchange. Returns { code, tokens }. */
async function codeFlow(token, clientId, scope) {
  const { verifier, challenge } = pkce();
  const a = await srv.api('/hhttps/oauth/approve', {
    method: 'POST',
    body: { token, client_id: clientId, redirect_uri: REDIRECT_URI, scope,
            code_challenge: challenge, code_challenge_method: 'S256' }
  });
  assert.equal(a.status, 200, a.text);
  const code = new URL(a.json.redirect).searchParams.get('code');
  assert.ok(code, 'code in redirect');

  const t = await srv.api('/hhttps/oauth/token', {
    method: 'POST',
    body: { grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI,
            client_id: clientId, code_verifier: verifier }
  });
  assert.equal(t.status, 200, t.text);
  return { code, tokens: t.json };
}

function assertMethodClaims(p, pseudonym) {
  assert.ok(Array.isArray(p.verified_methods), 'verified_methods is an array');
  assert.ok(p.verified_methods.includes('email'), 'verified_methods contains email');
  assert.equal(p.email_verified, true);
  assert.equal(p.passkey_verified, false);
  assert.equal(p.github_verified, false);
  assert.equal(p.eudi_verified, false);
  assert.equal(p.preferred_username, pseudonym);
}

// ─── AK-17 / AK-18 / AK-21: scope "openid email" ────────────────────────────

test('AK-17/AK-18: scope "openid email" → id_token + access_token + userinfo carry email, flags, preferred_username; email wiped from code row', { skip }, async () => {
  const email = `T6-Mixed-${rnd()}@Example.org`;
  const clientId = await createClient();
  const { token } = await hhttpsToken(email, { pseudonym: 'Anna' });

  const { code, tokens } = await codeFlow(token, clientId, 'openid email');
  assert.ok(tokens.id_token, 'id_token present');
  assert.ok(tokens.access_token, 'access_token present');

  const id = decodeJwtPayload(tokens.id_token);
  assert.equal(id.email, email.toLowerCase(), 'AK-17: email claim (normalized)');
  assert.equal(id.email_verified, true);
  assertMethodClaims(id, 'Anna');

  const at = decodeJwtPayload(tokens.access_token);
  assert.equal(at.email, email.toLowerCase(), 'AK-18: access token carries email');
  assertMethodClaims(at, 'Anna');

  // AK-17: transferred ⇒ deleted on the code row
  const rows = await sql('SELECT email, pseudonym, used FROM authorization_codes WHERE code = $1', [code]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].used, true);
  assert.equal(rows[0].email, null, 'email wiped from authorization_codes after claim');
  assert.equal(rows[0].pseudonym, 'Anna');

  // userinfo reads only from the access token
  const u = await srv.api('/hhttps/oauth/userinfo', { headers: { authorization: `Bearer ${tokens.access_token}` } });
  assert.equal(u.status, 200, u.text);
  assert.equal(u.json.sub, id.sub);
  assert.equal(u.json.email, email.toLowerCase());
  assertMethodClaims(u.json, 'Anna');
});

// ─── AK-3: same sub across sessions; scope without email ────────────────────

test('AK-3: second session with the same email (other spelling) → same sub; scope "openid" → no email claim but flags + preferred_username', { skip }, async () => {
  const email = freshEmail();
  const clientId = await createClient();

  const first = await hhttpsToken(email, { pseudonym: 'Anna' });
  const r1 = await codeFlow(first.token, clientId, 'openid email');
  const id1 = decodeJwtPayload(r1.tokens.id_token);
  assert.equal(id1.email, email);

  const second = await hhttpsToken(`  ${email.toUpperCase()} `);
  assert.equal(second.userId, first.userId, 'same anchor userId');
  const r2 = await codeFlow(second.token, clientId, 'openid');
  const id2 = decodeJwtPayload(r2.tokens.id_token);

  assert.equal(id2.sub, id1.sub, 'AK-3: same pairwise sub for the same platform');
  assert.equal(id2.email, undefined, 'no email claim without scope email');
  assert.equal(id2.email_verified, true);
  assert.equal(id2.preferred_username, 'Anna');
  assertMethodClaims(id2, 'Anna');

  const at2 = decodeJwtPayload(r2.tokens.access_token);
  assert.equal(at2.email, undefined);
  const u = await srv.api('/hhttps/oauth/userinfo', { headers: { authorization: `Bearer ${r2.tokens.access_token}` } });
  assert.equal(u.status, 200, u.text);
  assert.equal(u.json.email, undefined, 'userinfo: no email without scope');
  assertMethodClaims(u.json, 'Anna');

  // the code row for the openid-only flow never carried the email
  const rows = await sql('SELECT email FROM authorization_codes WHERE code = $1', [r2.code]);
  assert.equal(rows[0].email, null);
});

// ─── Refresh grant ──────────────────────────────────────────────────────────

test('refresh_token grant: new access_token keeps preferred_username, verified_methods, flags and email', { skip }, async () => {
  const email = freshEmail();
  const clientId = await createClient();
  const { token } = await hhttpsToken(email, { pseudonym: 'Anna' });
  const { tokens } = await codeFlow(token, clientId, 'openid email');
  assert.ok(tokens.refresh_token, 'refresh_token issued');

  const r = await srv.api('/hhttps/oauth/token', {
    method: 'POST',
    body: { grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: clientId }
  });
  assert.equal(r.status, 200, r.text);
  const at = decodeJwtPayload(r.json.access_token);
  assert.equal(at.email, email);
  assertMethodClaims(at, 'Anna');

  // rotated refresh JWT carries the claims for the next rotation too
  const rd = decodeJwtPayload(r.json.refresh_token);
  assert.equal(rd.preferred_username, 'Anna');
  assert.equal(rd.email, email);
  assert.ok(rd.verified_methods.includes('email'));

  const u = await srv.api('/hhttps/oauth/userinfo', { headers: { authorization: `Bearer ${r.json.access_token}` } });
  assert.equal(u.status, 200, u.text);
  assert.equal(u.json.email, email);
  assertMethodClaims(u.json, 'Anna');
});

// ─── AK-19: scope email not allowed for the client ──────────────────────────

test('AK-19: client without "email" in allowed_scopes → authorize redirects with error=invalid_scope', { skip }, async () => {
  const clientId = await createClient(['openid']);
  const { challenge } = pkce();
  const qs = new URLSearchParams({
    response_type: 'code', client_id: clientId, redirect_uri: REDIRECT_URI,
    scope: 'openid email', state: 'xyz', code_challenge: challenge, code_challenge_method: 'S256'
  });
  const res = await fetch(`${srv.baseUrl}/hhttps/oauth/authorize?${qs}`, { redirect: 'manual' });
  assert.equal(res.status, 302, await res.text());
  const loc = new URL(res.headers.get('location'));
  assert.equal(loc.origin + loc.pathname, REDIRECT_URI);
  assert.equal(loc.searchParams.get('error'), 'invalid_scope');
  assert.equal(loc.searchParams.get('state'), 'xyz');
});

test('AK-19 (positive): client with "email" allowed → authorize renders the consent page with the email scope row', { skip }, async () => {
  const clientId = await createClient();
  const { challenge } = pkce();
  const qs = new URLSearchParams({
    response_type: 'code', client_id: clientId, redirect_uri: REDIRECT_URI,
    scope: 'openid email', code_challenge: challenge, code_challenge_method: 'S256'
  });
  const res = await fetch(`${srv.baseUrl}/hhttps/oauth/authorize?${qs}`, { redirect: 'manual' });
  assert.equal(res.status, 200);
  const html = await res.text();
  assert.match(html, /data-scope="email"/);
  assert.match(html, /E-Mail-Adresse/);
});

// ─── AK-20: discovery ───────────────────────────────────────────────────────

test('AK-20: discovery lists scope email and the new claims', { skip }, async () => {
  const r = await srv.api('/.well-known/openid-configuration');
  assert.equal(r.status, 200, r.text);
  assert.ok(r.json.scopes_supported.includes('email'));
  for (const c of ['email', 'email_verified', 'passkey_verified', 'github_verified', 'eudi_verified', 'verified_methods', 'preferred_username']) {
    assert.ok(r.json.claims_supported.includes(c), `claims_supported contains ${c}`);
  }
});
