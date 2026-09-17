// Review wave 2 / AP2 (#59, #68, #77, #96, #105, #114, #131): error paths of
// the OAuth token endpoint, atomic refresh rotation, RFC 7009 revocation,
// the user disconnect, /userinfo token typing and the PAIRWISE_SECRET boot
// guard. Harness as in oauth-params.test.mjs: server.js as a child process,
// test clients written straight into oauth_clients, flow session → email →
// role/declare → approve → token.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { startServer, pgAvailable } from '../helpers/server.mjs';
import { sql, closeDb } from '../helpers/db.mjs';
import { rnd, freshEmail as mkEmail, verifyEmail, decodeJwtPayload, createTracker } from '../helpers/identity-flow.mjs';

const skip = !pgAvailable() && 'TEST_PG_HOST not set';
const REDIRECT_URI = 'http://localhost/cb';

let srv;
// One verified human for the whole file (the session endpoints are rate
// limited per server instance; an HHTTPS token can approve any number of codes).
let hh, hhUserId;
const track = createTracker();
const clientIds = new Set();
const operatorIds = new Set();

test.before(async () => {
  if (skip) return;
  srv = await startServer({ env: { SMTP_HOST: '', SMTP_USER: '', SMTP_PASS: '', GITHUB_CLIENT_ID: '', GITHUB_CLIENT_SECRET: '' } });
  const { sessionId, userId } = await verifyEmail(srv, mkEmail('ap2'), undefined, track);
  const d = await srv.api('/hhttps/role/declare', { method: 'POST', body: { sessionId } });
  assert.equal(d.status, 200, d.text);
  hh = d.json.hhttps.token;
  hhUserId = userId;
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
  const ops = [...operatorIds];
  if (ops.length) {
    await sql(`DELETE FROM tokens WHERE operator_id = ANY($1)`, [ops]).catch(() => {});
    await sql('DELETE FROM connected_platforms WHERE user_id = ANY($1)', [ops.map(o => 'machine:' + o)]);
    await sql('DELETE FROM machine_operators WHERE operator_id = ANY($1)', [ops]);
  }
  await track.cleanup();
  await srv.stop();
  await closeDb();
});

/** Test client; `secret` → confidential client (client_secret_hash set). */
async function createClient({ secret = null, allowedScopes = ['openid', 'role', 'email'] } = {}) {
  const clientId = `test-ap2-${rnd()}`;
  const hash = secret ? crypto.createHash('sha256').update(secret).digest('hex') : null;
  await sql(
    `INSERT INTO oauth_clients
       (client_id, client_secret_hash, name, homepage_url, redirect_uris, allowed_scopes,
        subject_type, verified, is_active, verification_status)
     VALUES ($1, $2, $3, $4, $5, $6, 'pairwise', TRUE, TRUE, 'verified')`,
    [clientId, hash, `AP2 test client ${clientId}`, 'http://localhost', JSON.stringify([REDIRECT_URI]), JSON.stringify(allowedScopes)]
  );
  clientIds.add(clientId);
  return clientId;
}

function pkce() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

async function seedOperator(contactEmail) {
  const operatorId = 'op-ap2-' + rnd();
  const apiKey = 'mk-' + crypto.randomBytes(24).toString('hex');
  const apiKeyHash = crypto.createHash('sha256').update(apiKey).digest('hex');
  await sql(
    `INSERT INTO machine_operators (operator_id, operator_name, purpose, contact_email, api_key_hash)
     VALUES ($1, 'AP2 Bot', 'review test', $2, $3)`,
    [operatorId, contactEmail, apiKeyHash]
  );
  operatorIds.add(operatorId);
  return { operatorId, apiKey };
}

/** approve → code (PKCE S256). Returns { code, verifier }. */
async function getCode(token, clientId, scope = 'openid') {
  const { verifier, challenge } = pkce();
  const a = await srv.api('/hhttps/oauth/approve', { method: 'POST', body: {
    token, client_id: clientId, redirect_uri: REDIRECT_URI, scope,
    code_challenge: challenge, code_challenge_method: 'S256'
  } });
  assert.equal(a.status, 200, a.text);
  return { code: new URL(a.json.redirect).searchParams.get('code'), verifier };
}

const tokenReq = (body) => srv.api('/hhttps/oauth/token', { method: 'POST', body });

async function exchange(token, clientId, { scope = 'openid', secret } = {}) {
  const { code, verifier } = await getCode(token, clientId, scope);
  const t = await tokenReq({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI,
                             client_id: clientId, code_verifier: verifier, ...(secret ? { client_secret: secret } : {}) });
  assert.equal(t.status, 200, t.text);
  return t.json;
}

const userinfo = (bearer) => srv.api('/hhttps/oauth/userinfo', { headers: { authorization: `Bearer ${bearer}` } });

/** GET /hhttps/oauth/authorize without following the error redirect. */
function authorize(qs) {
  return fetch(`${srv.baseUrl}/hhttps/oauth/authorize?${qs}`, { redirect: 'manual' });
}

// ─── AP2-08 (#96): token endpoint error paths ────────────────────────────────

test('AP2-08: code reuse → invalid_grant (second exchange fails)', { skip }, async () => {
  const clientId = await createClient();
  const { code, verifier } = await getCode(hh, clientId);
  const body = { grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI, client_id: clientId, code_verifier: verifier };
  const first = await tokenReq(body);
  assert.equal(first.status, 200, first.text);
  const second = await tokenReq(body);
  assert.equal(second.status, 400, second.text);
  assert.equal(second.json.error, 'invalid_grant');
});

test('AP2-08: PKCE verifier mismatch → invalid_grant', { skip }, async () => {
  const clientId = await createClient();
  const { code } = await getCode(hh, clientId);
  const t = await tokenReq({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI,
                             client_id: clientId, code_verifier: pkce().verifier });
  assert.equal(t.status, 400, t.text);
  assert.equal(t.json.error, 'invalid_grant');
  assert.match(t.json.error_description, /PKCE/);
});

test('AP2-08: client_id mismatch / redirect_uri mismatch → invalid_grant', { skip }, async () => {
  const clientA = await createClient();
  const clientB = await createClient();

  const c1 = await getCode(hh, clientA);
  const t1 = await tokenReq({ grant_type: 'authorization_code', code: c1.code, redirect_uri: REDIRECT_URI,
                              client_id: clientB, code_verifier: c1.verifier });
  assert.equal(t1.status, 400, t1.text);
  assert.equal(t1.json.error, 'invalid_grant');
  assert.match(t1.json.error_description, /client mismatch/);

  const c2 = await getCode(hh, clientA);
  const t2 = await tokenReq({ grant_type: 'authorization_code', code: c2.code, redirect_uri: 'http://localhost/other',
                              client_id: clientA, code_verifier: c2.verifier });
  assert.equal(t2.status, 400, t2.text);
  assert.equal(t2.json.error, 'invalid_grant');
  assert.match(t2.json.error_description, /redirect_uri/);
});

test('AP2-08: confidential client without / with wrong secret → 401 invalid_client; correct secret → 200', { skip }, async () => {
  const secret = 'cs-' + rnd();
  const clientId = await createClient({ secret });

  const c1 = await getCode(hh, clientId);
  const noSecret = await tokenReq({ grant_type: 'authorization_code', code: c1.code, redirect_uri: REDIRECT_URI,
                                    client_id: clientId, code_verifier: c1.verifier });
  assert.equal(noSecret.status, 401, noSecret.text);
  assert.equal(noSecret.json.error, 'invalid_client');

  const wrong = await tokenReq({ grant_type: 'authorization_code', code: c1.code, redirect_uri: REDIRECT_URI,
                                 client_id: clientId, code_verifier: c1.verifier, client_secret: 'nope' });
  assert.equal(wrong.status, 401, wrong.text);
  assert.equal(wrong.json.error, 'invalid_client');

  // The client auth failures above must not have consumed the code.
  const ok = await tokenReq({ grant_type: 'authorization_code', code: c1.code, redirect_uri: REDIRECT_URI,
                              client_id: clientId, code_verifier: c1.verifier, client_secret: secret });
  assert.equal(ok.status, 200, ok.text);
  assert.ok(ok.json.access_token);
});

test('AP2-08: grant_type=password → unsupported_grant_type; unknown client → invalid_client', { skip }, async () => {
  const clientId = await createClient();
  const t = await tokenReq({ grant_type: 'password', client_id: clientId, username: 'a', password: 'b' });
  assert.equal(t.status, 400, t.text);
  assert.equal(t.json.error, 'unsupported_grant_type');

  const u = await tokenReq({ grant_type: 'authorization_code', code: 'hp-x', redirect_uri: REDIRECT_URI, client_id: 'no-such-client' });
  assert.equal(u.status, 401, u.text);
  assert.equal(u.json.error, 'invalid_client');
});

test('AP2-08: refresh grant with a foreign client_id → invalid_grant; the token stays usable by its own client', { skip }, async () => {
  const clientA = await createClient();
  const clientB = await createClient();
  const tokens = await exchange(hh, clientA);
  assert.ok(tokens.refresh_token, 'refresh_token issued');

  const foreign = await tokenReq({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: clientB });
  assert.equal(foreign.status, 400, foreign.text);
  assert.equal(foreign.json.error, 'invalid_grant');

  const own = await tokenReq({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: clientA });
  assert.equal(own.status, 200, own.text);
  assert.ok(own.json.access_token && own.json.refresh_token);
});

test('AP2-08: refresh with an already rotated token → invalid_grant', { skip }, async () => {
  const clientId = await createClient();
  const tokens = await exchange(hh, clientId);
  const r1 = await tokenReq({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: clientId });
  assert.equal(r1.status, 200, r1.text);
  const r2 = await tokenReq({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: clientId });
  assert.equal(r2.status, 400, r2.text);
  assert.equal(r2.json.error, 'invalid_grant');
  // …and the successor still works.
  const r3 = await tokenReq({ grant_type: 'refresh_token', refresh_token: r1.json.refresh_token, client_id: clientId });
  assert.equal(r3.status, 200, r3.text);
});

// ─── AP2-03 (#68): atomic rotation ───────────────────────────────────────────

test('AP2-03: 30 parallel refreshes with the same token → exactly one 200, exactly one active successor row', { skip }, async () => {
  const clientId = await createClient();
  const tokens = await exchange(hh, clientId);
  const oldJti = decodeJwtPayload(tokens.refresh_token).jti;
  const body = JSON.stringify({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: clientId });

  const results = await Promise.all(Array.from({ length: 30 }, () =>
    fetch(srv.baseUrl + '/hhttps/oauth/token', { method: 'POST', headers: { 'content-type': 'application/json' }, body })
      .then(async r => ({ status: r.status, json: await r.json() }))));
  const ok = results.filter(r => r.status === 200);
  assert.equal(ok.length, 1, `exactly one refresh wins (got ${ok.length})`);
  assert.ok(results.filter(r => r.status === 400).every(r => r.json.error === 'invalid_grant'), 'losers get invalid_grant');
  assert.equal(results.filter(r => r.status >= 500).length, 0, 'no server errors');

  const newJti = decodeJwtPayload(ok[0].json.refresh_token).jti;
  const rows = await sql('SELECT jti FROM refresh_tokens WHERE jti = ANY($1)', [[oldJti, newJti]]);
  assert.deepEqual(rows.map(r => r.jti), [newJti], 'old jti gone, only the winner\'s successor is active');
});

// ─── AP2-04 (#77): non-string parameters → 400, never a hang ─────────────────

test('AP2-04: /token with client_secret / code_verifier / refresh_token as non-strings → 400 invalid_request, code NOT consumed', { skip }, async () => {
  const clientId = await createClient();
  const { code, verifier } = await getCode(hh, clientId);

  const n = await tokenReq({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI, client_id: clientId, code_verifier: verifier, client_secret: 123 });
  assert.equal(n.status, 400, n.text);
  assert.equal(n.json.error, 'invalid_request');
  assert.match(n.json.error_description, /client_secret/);

  const o = await tokenReq({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI, client_id: clientId, code_verifier: {} });
  assert.equal(o.status, 400, o.text);
  assert.equal(o.json.error, 'invalid_request');

  const a = await tokenReq({ grant_type: 'authorization_code', code: [code], redirect_uri: REDIRECT_URI, client_id: clientId, code_verifier: verifier });
  assert.equal(a.status, 400, a.text);

  const r = await tokenReq({ grant_type: 'refresh_token', refresh_token: { x: 1 }, client_id: clientId, client_secret: {} });
  assert.equal(r.status, 400, r.text);
  assert.equal(r.json.error, 'invalid_request');

  // Validation happens before the claim: the code is still exchangeable.
  const ok = await tokenReq({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI, client_id: clientId, code_verifier: verifier });
  assert.equal(ok.status, 200, ok.text);
});

test('AP2-04: /authorize with scope[] → 302 error=invalid_request; /approve with scope[] → 400 invalid_request', { skip }, async () => {
  const clientId = await createClient();
  const { challenge } = pkce();
  const qs = new URLSearchParams({ response_type: 'code', client_id: clientId, redirect_uri: REDIRECT_URI,
                                   code_challenge: challenge, code_challenge_method: 'S256' });
  qs.append('scope[]', 'openid');
  qs.append('scope[]', 'email');
  const r = await authorize(qs.toString());
  assert.equal(r.status, 302, 'redirect with error instead of a hang/TypeError');
  const loc = new URL(r.headers.get('location'));
  assert.equal(loc.searchParams.get('error'), 'invalid_request');
  assert.match(loc.searchParams.get('error_description'), /scope/);

  const a = await srv.api('/hhttps/oauth/approve', { method: 'POST', body: {
    token: hh, client_id: clientId, redirect_uri: REDIRECT_URI, scope: ['openid'],
    code_challenge: challenge, code_challenge_method: 'S256'
  } });
  assert.equal(a.status, 400, a.text);
  assert.equal(a.json.error, 'invalid_request');
});

// ─── AP2-10 (#105): /userinfo accepts access tokens only ─────────────────────

test('AP2-10: /userinfo rejects the refresh JWT, an HHTTPS session token and garbage with 401 invalid_token + WWW-Authenticate', { skip }, async () => {
  const clientId = await createClient();
  const tokens = await exchange(hh, clientId, { scope: 'openid email' });
  assert.equal(decodeJwtPayload(tokens.access_token).token_use, 'access');
  assert.equal(decodeJwtPayload(tokens.refresh_token).token_use, 'refresh');

  const good = await userinfo(tokens.access_token);
  assert.equal(good.status, 200, good.text);
  assert.ok(good.json.email, 'access token → email with scope email');

  for (const [name, bearer] of [['refresh JWT', tokens.refresh_token], ['HHTTPS session token', hh], ['id_token', tokens.id_token], ['garbage', 'x.y.z']]) {
    const r = await userinfo(bearer);
    assert.equal(r.status, 401, `${name}: ${r.text}`);
    assert.equal(r.json.error, 'invalid_token', name);
    assert.equal(r.json.email, undefined, `${name}: nothing leaks`);
    assert.match(r.headers.get('www-authenticate') || '', /Bearer .*error="invalid_token"/, `${name}: RFC 6750 header`);
  }

  // Rotated refresh JWT (old jti deleted) — the original repro of #105.
  const rot = await tokenReq({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: clientId });
  assert.equal(rot.status, 200, rot.text);
  const stale = await userinfo(tokens.refresh_token);
  assert.equal(stale.status, 401, stale.text);
  const fresh = await userinfo(rot.json.access_token);
  assert.equal(fresh.status, 200, fresh.text);
});

// ─── AP2-02 (#59): RFC 7009 revocation + user disconnect ─────────────────────

test('AP2-02: POST /revoke (RFC 7009) with client auth deletes the refresh token → next refresh invalid_grant; invalid/foreign token still 200', { skip }, async () => {
  const secret = 'cs-' + rnd();
  const clientId = await createClient({ secret });
  const other = await createClient();
  const tokens = await exchange(hh, clientId, { secret });
  const jti = decodeJwtPayload(tokens.refresh_token).jti;

  const disco = await srv.api('/.well-known/openid-configuration');
  assert.equal(disco.json.revocation_endpoint, `${srv.baseUrl}/hhttps/oauth/revoke`);

  // client auth is required
  const noAuth = await srv.api('/hhttps/oauth/revoke', { method: 'POST', body: { token: tokens.refresh_token, client_id: clientId } });
  assert.equal(noAuth.status, 401, noAuth.text);
  assert.equal(noAuth.json.error, 'invalid_client');
  const noToken = await srv.api('/hhttps/oauth/revoke', { method: 'POST', body: { client_id: clientId, client_secret: secret } });
  assert.equal(noToken.status, 400, noToken.text);
  assert.equal(noToken.json.error, 'invalid_request');

  // a foreign client cannot revoke this token — but learns nothing (200)
  const foreign = await srv.api('/hhttps/oauth/revoke', { method: 'POST', body: { token: tokens.refresh_token, client_id: other, token_type_hint: 'refresh_token' } });
  assert.equal(foreign.status, 200, foreign.text);
  assert.equal((await sql('SELECT 1 FROM refresh_tokens WHERE jti = $1', [jti])).length, 1, 'still active');

  // garbage token → 200 as well (RFC 7009 §2.2)
  const junk = await srv.api('/hhttps/oauth/revoke', { method: 'POST', body: { token: 'not-a-jwt', client_id: clientId, client_secret: secret } });
  assert.equal(junk.status, 200, junk.text);

  const ok = await srv.api('/hhttps/oauth/revoke', { method: 'POST', body: { token: tokens.refresh_token, client_id: clientId, client_secret: secret, token_type_hint: 'refresh_token' } });
  assert.equal(ok.status, 200, ok.text);
  assert.equal((await sql('SELECT 1 FROM refresh_tokens WHERE jti = $1', [jti])).length, 0, 'refresh row deleted');

  const r = await tokenReq({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: clientId, client_secret: secret });
  assert.equal(r.status, 400, r.text);
  assert.equal(r.json.error, 'invalid_grant');

  // the access token needs no server state — revoking it is a 200 no-op
  const acc = await srv.api('/hhttps/oauth/revoke', { method: 'POST', body: { token: tokens.access_token, client_id: clientId, client_secret: secret, token_type_hint: 'access_token' } });
  assert.equal(acc.status, 200, acc.text);
});

test('AP2-02: POST /disconnect (user) sets connected_platforms.revoked_at — for humans and for machine actors', { skip }, async () => {
  const clientId = await createClient();

  // human
  const userId = hhUserId;
  await exchange(hh, clientId);
  let rows = await sql('SELECT revoked_at FROM connected_platforms WHERE user_id = $1 AND client_id = $2', [userId, clientId]);
  assert.equal(rows.length, 1, 'connection recorded');
  assert.equal(rows[0].revoked_at, null);

  const bad = await srv.api('/hhttps/oauth/disconnect', { method: 'POST', body: { token: 'nope', client_id: clientId } });
  assert.equal(bad.status, 401, bad.text);

  const dc = await srv.api('/hhttps/oauth/disconnect', { method: 'POST', body: { token: hh, client_id: clientId } });
  assert.equal(dc.status, 200, dc.text);
  assert.equal(dc.json.status, 'revoked');
  rows = await sql('SELECT revoked_at FROM connected_platforms WHERE user_id = $1 AND client_id = $2', [userId, clientId]);
  assert.ok(rows[0].revoked_at, 'revoked_at set for the human');

  // machine: user_id is 'machine:<operatorId>' (as in /approve)
  const { operatorId, apiKey } = await seedOperator(mkEmail('ap2op'));
  const mt = await srv.api('/hhttps/machine/token', { method: 'POST', body: { operatorId, apiKey } });
  assert.equal(mt.status, 200, mt.text);
  await exchange(mt.json.token, clientId);
  const mdc = await srv.api('/hhttps/oauth/disconnect', { method: 'POST', body: { token: mt.json.token, client_id: clientId } });
  assert.equal(mdc.status, 200, mdc.text);
  rows = await sql('SELECT revoked_at FROM connected_platforms WHERE user_id = $1 AND client_id = $2', ['machine:' + operatorId, clientId]);
  assert.equal(rows.length, 1, 'machine connection row exists');
  assert.ok(rows[0].revoked_at, 'revoked_at set for the machine actor');

  // Back-compat: /revoke keeps the user-disconnect semantics when an HHTTPS
  // bearer token is presented (the RFC 7009 path only takes over for platform
  // tokens) — AP2-01's response shape included.
  const c2 = await createClient();
  await exchange(hh, c2);
  const legacy = await srv.api('/hhttps/oauth/revoke', { method: 'POST', body: { token: hh, client_id: c2 } });
  assert.equal(legacy.status, 200, legacy.text);
  assert.equal(legacy.json.status, 'revoked');
  assert.ok(legacy.json.refresh_tokens_revoked >= 1, 'the platform refresh chain was ended');
  rows = await sql('SELECT revoked_at FROM connected_platforms WHERE user_id = $1 AND client_id = $2', [userId, c2]);
  assert.ok(rows[0].revoked_at, 'revoked_at set via /revoke too');
});

// ─── AP2-24 (#131): stats off the response path, still recorded ──────────────

test('AP2-24: token exchange records the connection before responding; stats counters catch up asynchronously', { skip }, async () => {
  const clientId = await createClient();
  const before = await sql(`SELECT metric, value FROM stats WHERE metric IN ('oauth_tokens_issued', 'oauth_logins')`);
  const val = (rows, m) => Number(rows.find(r => r.metric === m)?.value ?? 0);
  const userId = hhUserId;
  const tokens = await exchange(hh, clientId);
  assert.ok(tokens.refresh_token, 'refresh token issued');

  const cp = await sql('SELECT login_count FROM connected_platforms WHERE user_id = $1 AND client_id = $2', [userId, clientId]);
  assert.equal(cp.length, 1, 'connected_platforms row present at response time');

  let after;
  for (let i = 0; i < 40; i++) {
    after = await sql(`SELECT metric, value FROM stats WHERE metric IN ('oauth_tokens_issued', 'oauth_logins')`);
    if (val(after, 'oauth_tokens_issued') > val(before, 'oauth_tokens_issued') &&
        val(after, 'oauth_logins') > val(before, 'oauth_logins')) break;
    await new Promise(r => setTimeout(r, 50));
  }
  assert.ok(val(after, 'oauth_tokens_issued') > val(before, 'oauth_tokens_issued'), 'oauth_tokens_issued incremented');
  assert.ok(val(after, 'oauth_logins') > val(before, 'oauth_logins'), 'oauth_logins incremented');
});

// ─── AP2-15 (#114): PAIRWISE_SECRET is mandatory in production ───────────────

test('AP2-15: NODE_ENV=production without PAIRWISE_SECRET → boot refuses; with it → boots', { skip }, async () => {
  await assert.rejects(
    startServer({ env: { NODE_ENV: 'production', PAIRWISE_SECRET: '', SMTP_HOST: '', SMTP_USER: '', SMTP_PASS: '', GITHUB_CLIENT_ID: '', GITHUB_CLIENT_SECRET: '' } }),
    /PAIRWISE_SECRET/
  );
  const prod = await startServer({ env: { NODE_ENV: 'production', PAIRWISE_SECRET: 'test-pairwise-' + rnd(), SMTP_HOST: '', SMTP_USER: '', SMTP_PASS: '', GITHUB_CLIENT_ID: '', GITHUB_CLIENT_SECRET: '' } });
  try {
    const info = await prod.api('/hhttps/info');
    assert.equal(info.status, 200);
  } finally {
    await prod.stop();
  }
});
