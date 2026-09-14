// #31: authorization_codes.state/nonce/pkce_challenge were VARCHAR(128);
// clients that send longer `state`/`nonce` values (common with encrypted
// state blobs) made the code insert fail with "value too long for type
// character varying(128)" and the login broke with 401/500. The columns are
// now TEXT (boot-DDL migration-phase-3a1-authcodes-text.sql) and the input
// is validated up front (oauth-params.js): state/nonce ≤ 2048 chars,
// code_challenge 43–128 chars of [A-Za-z0-9._~-].
//
// Harness as in oauth-claims.test.mjs: server.js as a child process, a test
// client written straight into oauth_clients, flow session → email →
// role/declare → approve.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { startServer, pgAvailable } from '../helpers/server.mjs';
import { sql, closeDb } from '../helpers/db.mjs';
import { rnd, freshEmail as mkEmail, verifyEmail, createTracker } from '../helpers/identity-flow.mjs';

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
    await sql('DELETE FROM authorization_codes WHERE client_id = ANY($1)', [ids]);
    await sql('DELETE FROM connected_platforms WHERE client_id = ANY($1)', [ids]);
    await sql('DELETE FROM oauth_clients WHERE client_id = ANY($1)', [ids]);
  }
  await track.cleanup();
  await srv.stop();
  await closeDb();
});

async function createClient(allowedScopes = ['openid', 'role', 'email']) {
  const clientId = `test-t31-${rnd()}`;
  await sql(
    `INSERT INTO oauth_clients
       (client_id, client_secret_hash, name, homepage_url, redirect_uris, allowed_scopes,
        subject_type, verified, is_active, verification_status)
     VALUES ($1, NULL, $2, $3, $4, $5, 'pairwise', TRUE, TRUE, 'verified')`,
    [clientId, `#31 test client ${clientId}`, 'http://localhost', JSON.stringify([REDIRECT_URI]), JSON.stringify(allowedScopes)]
  );
  clientIds.add(clientId);
  return clientId;
}

function pkce() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

async function hhttpsToken() {
  const { sessionId } = await verifyEmail(srv, mkEmail('t31'), undefined, track);
  const d = await srv.api('/hhttps/role/declare', { method: 'POST', body: { sessionId } });
  assert.equal(d.status, 200, d.text);
  return d.json.hhttps.token;
}

function approve(body) {
  return srv.api('/hhttps/oauth/approve', { method: 'POST', body });
}

/** GET /hhttps/oauth/authorize without following the error redirect. */
function authorize(qs) {
  return fetch(`${srv.baseUrl}/hhttps/oauth/authorize?${qs}`, { redirect: 'manual' });
}

// ─── (a) long state/nonce is stored and echoed ───────────────────────────────

test('#31 (a): state of 1000 chars → approve 200, redirect echoes the state, code row stores state + nonce', { skip }, async () => {
  const clientId = await createClient();
  const token = await hhttpsToken();
  const { challenge } = pkce();
  const state = 's'.repeat(1000);
  const nonce = 'n'.repeat(1000);

  const a = await approve({ token, client_id: clientId, redirect_uri: REDIRECT_URI, scope: 'openid',
                            state, nonce, code_challenge: challenge, code_challenge_method: 'S256' });
  assert.equal(a.status, 200, a.text);
  const u = new URL(a.json.redirect);
  assert.equal(u.searchParams.get('state'), state, 'redirect carries the full state');
  const code = u.searchParams.get('code');
  assert.ok(code, 'code in redirect');

  const rows = await sql('SELECT state, nonce, pkce_challenge FROM authorization_codes WHERE code = $1', [code]);
  assert.equal(rows.length, 1, 'authorization_codes row stored');
  assert.equal(rows[0].state, state);
  assert.equal(rows[0].nonce, nonce);
  assert.equal(rows[0].pkce_challenge, challenge);
});

// ─── (b) approve rejects an over-long state with 400 invalid_request ────────

test('#31 (b): state of 5000 chars → approve 400 invalid_request', { skip }, async () => {
  const clientId = await createClient();
  const token = await hhttpsToken();
  const { challenge } = pkce();

  const a = await approve({ token, client_id: clientId, redirect_uri: REDIRECT_URI, scope: 'openid',
                            state: 'x'.repeat(5000), code_challenge: challenge, code_challenge_method: 'S256' });
  assert.equal(a.status, 400, a.text);
  assert.equal(a.json.error, 'invalid_request');
  assert.match(a.json.error_description, /state/);
});

// ─── (c) authorize redirects with error=invalid_request, state truncated ────

test('#31 (c): authorize with state of 5000 chars → 302 error=invalid_request (state not echoed at full length)', { skip }, async () => {
  const clientId = await createClient();
  const { challenge } = pkce();
  const qs = new URLSearchParams({
    response_type: 'code', client_id: clientId, redirect_uri: REDIRECT_URI, scope: 'openid',
    state: 'x'.repeat(5000), code_challenge: challenge, code_challenge_method: 'S256'
  });
  const r = await authorize(qs);
  assert.equal(r.status, 302, await r.text());
  const loc = new URL(r.headers.get('location'));
  assert.equal(loc.origin + loc.pathname, REDIRECT_URI);
  assert.equal(loc.searchParams.get('error'), 'invalid_request');
  assert.match(loc.searchParams.get('error_description') || '', /state/);
  const echoed = loc.searchParams.get('state') || '';
  assert.ok(echoed.length <= 2048, `state in error redirect is capped (got ${echoed.length})`);
});

// ─── (d) invalid code_challenge ─────────────────────────────────────────────

test('#31 (d): code_challenge "abc" → approve 400 invalid_request and authorize 302 error=invalid_request', { skip }, async () => {
  const clientId = await createClient();
  const token = await hhttpsToken();

  const a = await approve({ token, client_id: clientId, redirect_uri: REDIRECT_URI, scope: 'openid',
                            state: 'st', code_challenge: 'abc', code_challenge_method: 'S256' });
  assert.equal(a.status, 400, a.text);
  assert.equal(a.json.error, 'invalid_request');
  assert.match(a.json.error_description, /code_challenge/);

  const qs = new URLSearchParams({ response_type: 'code', client_id: clientId, redirect_uri: REDIRECT_URI,
                                   scope: 'openid', state: 'st', code_challenge: 'abc' });
  const r = await authorize(qs);
  assert.equal(r.status, 302, await r.text());
  const loc = new URL(r.headers.get('location'));
  assert.equal(loc.searchParams.get('error'), 'invalid_request');
  assert.equal(loc.searchParams.get('state'), 'st');
});

test('#31: unknown code_challenge_method → approve 400 invalid_request', { skip }, async () => {
  const clientId = await createClient();
  const token = await hhttpsToken();
  const { challenge } = pkce();
  const a = await approve({ token, client_id: clientId, redirect_uri: REDIRECT_URI, scope: 'openid',
                            code_challenge: challenge, code_challenge_method: 'S512' });
  assert.equal(a.status, 400, a.text);
  assert.equal(a.json.error, 'invalid_request');
  assert.match(a.json.error_description, /code_challenge_method/);
});

// ─── (e) schema: the three columns are TEXT after boot ──────────────────────

test('#31 (e): authorization_codes.state/nonce/pkce_challenge are TEXT after boot (migration-phase-3a1)', { skip }, async () => {
  const rows = await sql(
    `SELECT column_name, data_type FROM information_schema.columns
      WHERE table_name = 'authorization_codes' AND column_name IN ('state', 'nonce', 'pkce_challenge')
      ORDER BY column_name`
  );
  assert.deepEqual(rows, [
    { column_name: 'nonce', data_type: 'text' },
    { column_name: 'pkce_challenge', data_type: 'text' },
    { column_name: 'state', data_type: 'text' },
  ]);
});
