// Review wave 3 / AP2 — behaviour of the refactored OAuth routes.
//
//   AP2-06 (#198)  /approve enforces PKCE for public clients, like /authorize
//   AP2-28/29      the split token endpoint issues the same tokens as before
//   AP2-30 (#157)  one scope policy, one client authentication
//   AP2-31 (#165)  the consent page's script is a separate, served module
//   AP2-33 (#175)  every /hhttps/oauth/* route answers with RFC codes
//
// Harness as in oauth-token-errors.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { startServer, pgAvailable } from '../helpers/server.mjs';
import { sql, closeDb } from '../helpers/db.mjs';
import { rnd, freshEmail as mkEmail, verifyEmail, decodeJwtPayload, createTracker } from '../helpers/identity-flow.mjs';

const skip = !pgAvailable() && 'TEST_PG_HOST not set';
const REDIRECT_URI = 'http://localhost/cb';

let srv, hh;
const track = createTracker();
const clientIds = new Set();

test.before(async () => {
  if (skip) return;
  srv = await startServer({ env: { SMTP_HOST: '', SMTP_USER: '', SMTP_PASS: '', GITHUB_CLIENT_ID: '', GITHUB_CLIENT_SECRET: '' } });
  const { sessionId } = await verifyEmail(srv, mkEmail('w3ap2'), undefined, track);
  const d = await srv.api('/hhttps/role/declare', { method: 'POST', body: { sessionId } });
  assert.equal(d.status, 200, d.text);
  hh = d.json.hhttps.token;
});

test.after(async () => {
  if (skip) return;
  const ids = [...clientIds];
  if (ids.length) {
    await sql('DELETE FROM authorization_codes WHERE client_id = ANY($1)', [ids]);
    await sql('DELETE FROM connected_platforms WHERE client_id = ANY($1)', [ids]);
    await sql('DELETE FROM client_stats WHERE client_id = ANY($1)', [ids]).catch(() => {});
    await sql('DELETE FROM oauth_clients WHERE client_id = ANY($1)', [ids]);
  }
  await track.cleanup();
  await srv.stop();
  await closeDb();
});

async function createClient({ secret = null, allowedScopes = ['openid', 'role', 'email'] } = {}) {
  const clientId = `test-w3ap2-${rnd()}`;
  const hash = secret ? crypto.createHash('sha256').update(secret).digest('hex') : null;
  await sql(
    `INSERT INTO oauth_clients
       (client_id, client_secret_hash, name, homepage_url, redirect_uris, allowed_scopes,
        subject_type, verified, is_active, verification_status)
     VALUES ($1, $2, $3, $4, $5, $6, 'pairwise', TRUE, TRUE, 'verified')`,
    [clientId, hash, `W3 AP2 client ${clientId}`, 'http://localhost', JSON.stringify([REDIRECT_URI]), JSON.stringify(allowedScopes)]
  );
  clientIds.add(clientId);
  return clientId;
}

function pkce() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

const approve = (body) => srv.api('/hhttps/oauth/approve', { method: 'POST', body });
const tokenReq = (body) => srv.api('/hhttps/oauth/token', { method: 'POST', body });

// ─── AP2-06 (#198): PKCE is mandatory for public clients at /approve too ─────

test('AP2-06: a public client cannot get a code without code_challenge — and no row is written', { skip }, async () => {
  const clientId = await createClient();

  const a = await approve({ token: hh, client_id: clientId, redirect_uri: REDIRECT_URI, scope: 'openid' });
  assert.equal(a.status, 400, a.text);
  assert.equal(a.json.error, 'invalid_request');
  assert.match(a.json.error_description, /PKCE code_challenge is required for public clients/);
  assert.equal((await sql('SELECT 1 FROM authorization_codes WHERE client_id = $1', [clientId])).length, 0,
    'no pkce_challenge = NULL code was created');

  // With a challenge the same call succeeds (nothing else changed).
  const { challenge } = pkce();
  const ok = await approve({ token: hh, client_id: clientId, redirect_uri: REDIRECT_URI, scope: 'openid',
                             code_challenge: challenge, code_challenge_method: 'S256' });
  assert.equal(ok.status, 200, ok.text);
});

test('AP2-06: a confidential client may still approve without PKCE (secret authentication)', { skip }, async () => {
  const secret = 'sec-' + rnd();
  const clientId = await createClient({ secret });

  const a = await approve({ token: hh, client_id: clientId, redirect_uri: REDIRECT_URI, scope: 'openid' });
  assert.equal(a.status, 200, a.text);
  const code = new URL(a.json.redirect).searchParams.get('code');

  const t = await tokenReq({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI,
                             client_id: clientId, client_secret: secret });
  assert.equal(t.status, 200, t.text);
  assert.equal(decodeJwtPayload(t.json.access_token).token_use, 'access');
});

// ─── AP2-33 (#175): RFC 6749/6750 error codes on every route ─────────────────

test('AP2-33: /approve answers with RFC codes plus error_description', { skip }, async () => {
  const clientId = await createClient({ allowedScopes: ['openid', 'role'] });
  const { challenge } = pkce();
  const base = { client_id: clientId, redirect_uri: REDIRECT_URI, scope: 'openid',
                 code_challenge: challenge, code_challenge_method: 'S256' };

  const noToken = await approve({ ...base });
  assert.equal(noToken.status, 401, noToken.text);
  assert.equal(noToken.json.error, 'invalid_token');
  assert.match(noToken.json.error_description, /token required/);

  const badToken = await approve({ ...base, token: 'not.a.jwt' });
  assert.equal(badToken.status, 401, badToken.text);
  assert.equal(badToken.json.error, 'invalid_token');
  assert.ok(badToken.json.error_description, 'the original message is kept as a description');

  const unknownClient = await approve({ ...base, token: hh, client_id: 'does-not-exist-' + rnd() });
  assert.equal(unknownClient.status, 400, unknownClient.text);
  assert.equal(unknownClient.json.error, 'invalid_client');

  const badRedirect = await approve({ ...base, token: hh, redirect_uri: 'http://localhost/elsewhere' });
  assert.equal(badRedirect.status, 400, badRedirect.text);
  assert.equal(badRedirect.json.error, 'invalid_request');
  assert.match(badRedirect.json.error_description, /redirect_uri/);

  const noOpenid = await approve({ ...base, token: hh, scope: 'role' });
  assert.equal(noOpenid.status, 400, noOpenid.text);
  assert.equal(noOpenid.json.error, 'invalid_scope');
  assert.match(noOpenid.json.error_description, /openid/);

  const denied = await approve({ ...base, token: hh, scope: 'openid email' });
  assert.equal(denied.status, 400, denied.text);
  assert.equal(denied.json.error, 'invalid_scope');
  assert.match(denied.json.error_description, /may not request/);
});

test('AP2-33: /userinfo without a bearer token → 401 invalid_token + WWW-Authenticate', { skip }, async () => {
  const r = await srv.api('/hhttps/oauth/userinfo');
  assert.equal(r.status, 401, r.text);
  assert.equal(r.json.error, 'invalid_token');
  assert.match(r.headers.get('www-authenticate') || '', /Bearer .*error="invalid_token"/);
});

test('AP2-33: /disconnect answers with RFC codes', { skip }, async () => {
  const clientId = await createClient();

  const missing = await srv.api('/hhttps/oauth/disconnect', { method: 'POST', body: { client_id: clientId } });
  assert.equal(missing.status, 400, missing.text);
  assert.equal(missing.json.error, 'invalid_request');
  assert.match(missing.json.error_description, /token/);

  const bad = await srv.api('/hhttps/oauth/disconnect', { method: 'POST', body: { token: 'nope', client_id: clientId } });
  assert.equal(bad.status, 401, bad.text);
  assert.equal(bad.json.error, 'invalid_token');
  assert.ok(bad.json.error_description, 'the checkTokenValid message survives as a description');
});

// ─── AP2-28/29: the split grants still mint the same tokens ──────────────────

test('AP2-28/29: code grant and refresh grant produce the same claim set', { skip }, async () => {
  const clientId = await createClient({ allowedScopes: ['openid', 'role', 'email', 'age_group'] });
  const { verifier, challenge } = pkce();

  const a = await approve({ token: hh, client_id: clientId, redirect_uri: REDIRECT_URI,
                            scope: 'openid role email', code_challenge: challenge, code_challenge_method: 'S256' });
  assert.equal(a.status, 200, a.text);
  const code = new URL(a.json.redirect).searchParams.get('code');

  const t = await tokenReq({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI,
                             client_id: clientId, code_verifier: verifier });
  assert.equal(t.status, 200, t.text);
  assert.ok(t.json.refresh_token, 'a refresh token was issued');

  const r = await tokenReq({ grant_type: 'refresh_token', refresh_token: t.json.refresh_token, client_id: clientId });
  assert.equal(r.status, 200, r.text);

  const first  = decodeJwtPayload(t.json.access_token);
  const second = decodeJwtPayload(r.json.access_token);
  const drop = (p) => { const o = { ...p }; delete o.iat; delete o.exp; return o; };
  assert.deepEqual(drop(second), drop(first),
    'the access token from the refresh grant is claim-for-claim the one from the code grant');
  assert.equal(second.sub, first.sub, 'same pairwise subject');
  assert.equal(r.json.scope, t.json.scope);

  // The refresh JWTs agree too (apart from their rotating jti).
  const rf1 = decodeJwtPayload(t.json.refresh_token);
  const rf2 = decodeJwtPayload(r.json.refresh_token);
  assert.notEqual(rf1.jti, rf2.jti, 'rotation');
  const dropJti = (p) => { const o = drop(p); delete o.jti; return o; };
  assert.deepEqual(dropJti(rf2), dropJti(rf1));
});

test('AP2-30: both grants reject a wrong client secret with 401 invalid_client', { skip }, async () => {
  const secret = 'sec-' + rnd();
  const clientId = await createClient({ secret });
  const { verifier, challenge } = pkce();

  const a = await approve({ token: hh, client_id: clientId, redirect_uri: REDIRECT_URI, scope: 'openid',
                            code_challenge: challenge, code_challenge_method: 'S256' });
  const code = new URL(a.json.redirect).searchParams.get('code');

  for (const wrong of [undefined, '', 'nope', secret + 'x']) {
    const bad = await tokenReq({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI,
                                 client_id: clientId, client_secret: wrong, code_verifier: verifier });
    assert.equal(bad.status, 401, `${wrong}: ${bad.text}`);
    assert.equal(bad.json.error, 'invalid_client');
  }

  const good = await tokenReq({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI,
                                client_id: clientId, client_secret: secret, code_verifier: verifier });
  assert.equal(good.status, 200, good.text);

  const badRefresh = await tokenReq({ grant_type: 'refresh_token', refresh_token: good.json.refresh_token,
                                      client_id: clientId, client_secret: 'nope' });
  assert.equal(badRefresh.status, 401, badRefresh.text);
  assert.equal(badRefresh.json.error, 'invalid_client');
});

// ─── AP2-31 (#165): the consent page's assets ────────────────────────────────

test('AP2-31: the consent page links its CSS and module, and both are served', { skip }, async () => {
  const clientId = await createClient();
  const q = new URLSearchParams({
    response_type: 'code', client_id: clientId, redirect_uri: REDIRECT_URI, scope: 'openid role',
    state: 'st-' + rnd(), code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256'
  });
  const page = await fetch(`${srv.baseUrl}/hhttps/oauth/authorize?${q}`, { redirect: 'manual' });
  assert.equal(page.status, 200);
  const html = await page.text();

  assert.match(html, /<link rel="stylesheet" href="\/consent\.css">/);
  assert.match(html, /<script type="module" src="\/hhttps\/oauth\/consent\.js"><\/script>/);
  assert.doesNotMatch(html, /<style>/, 'no inline CSS left');
  assert.doesNotMatch(html, /addEventListener/, 'no inline browser JS left');

  const cfg = JSON.parse(html.match(/id="consent-config">([\s\S]*?)<\/script>/)[1]);
  assert.equal(cfg.base, srv.baseUrl.replace(/\/$/, ''), 'the script gets BASE_URL, not a hard-coded host');
  assert.equal(new URLSearchParams(cfg.params).get('client_id'), clientId);

  const css = await fetch(`${srv.baseUrl}/consent.css`);
  assert.equal(css.status, 200);
  assert.match(css.headers.get('content-type') || '', /text\/css/);

  const js = await fetch(`${srv.baseUrl}/hhttps/oauth/consent.js`);
  assert.equal(js.status, 200);
  assert.match(js.headers.get('content-type') || '', /javascript/);
  const body = await js.text();
  assert.match(body, /export const CONSENT_I18N/, 'the served file is the module itself');
  assert.match(body, /initConsentPage/);
});

test('AP2-31: the scope rows are rendered from the shared i18n table', { skip }, async () => {
  const clientId = await createClient({ allowedScopes: ['openid', 'role', 'email'] });
  const q = new URLSearchParams({
    response_type: 'code', client_id: clientId, redirect_uri: REDIRECT_URI, scope: 'openid email',
    code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256'
  });
  const html = await (await fetch(`${srv.baseUrl}/hhttps/oauth/authorize?${q}`, { redirect: 'manual' })).text();
  const { CONSENT_I18N } = await import('../../consent-client.js');

  assert.match(html, /data-scope="openid"/);
  assert.match(html, /data-scope="email"/);
  assert.doesNotMatch(html, /data-scope="role"/, 'only the requested scopes are listed');
  assert.ok(html.includes(CONSENT_I18N.de['scope.email.title']), 'the DE label comes from CONSENT_I18N');
  assert.ok(html.includes(CONSENT_I18N.de['consent.allow']), 'so does the button text');
});
