// T9 / AK-29: GET /hhttps/oauth/authorize carries `login_hint` (a syntactic
// e-mail, normalised, ≤ 254 chars) and `pseudonym` (sanitizePseudonym) into
// the consent page's embedded params — invalid values are silently dropped,
// never echoed. AK-30: the consent page's relogin() forwards both to the
// sign-in page and pre-fills #pseudoInput from the params (DOM, not HTML).
import test from 'node:test';
import assert from 'node:assert/strict';
import { startServer, pgAvailable } from '../helpers/server.mjs';
import { sql, closeDb } from '../helpers/db.mjs';
import { rnd } from '../helpers/identity-flow.mjs';

const skip = !pgAvailable() && 'TEST_PG_HOST not set';
const REDIRECT_URI = 'http://localhost/cb';

let srv;
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
  await srv.stop();
  await closeDb();
});

/** Public (PKCE) test client written straight into oauth_clients. */
async function createClient() {
  const clientId = `test-t9-${rnd()}`;
  await sql(
    `INSERT INTO oauth_clients
       (client_id, client_secret_hash, name, homepage_url, redirect_uris, allowed_scopes,
        subject_type, verified, is_active, verification_status)
     VALUES ($1, NULL, $2, $3, $4, $5, 'pairwise', TRUE, TRUE, 'verified')`,
    [clientId, `T9 test client ${clientId}`, 'http://localhost', JSON.stringify([REDIRECT_URI]), JSON.stringify(['openid', 'role', 'email'])]
  );
  clientIds.add(clientId);
  return clientId;
}

/** GET authorize with a valid base request plus `extra` query params → { status, body, params }. */
async function authorize(clientId, extra = {}) {
  const q = new URLSearchParams({
    response_type: 'code', client_id: clientId, redirect_uri: REDIRECT_URI, scope: 'openid role',
    state: 'st-' + rnd(), code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256',
    ...extra,
  });
  const res = await fetch(`${srv.baseUrl}/hhttps/oauth/authorize?${q}`, { redirect: 'manual' });
  const body = await res.text();
  // The consent page embeds `const params = new URLSearchParams("…");`
  const m = body.match(/new URLSearchParams\((".*?")\)/);
  const paramsStr = m ? JSON.parse(m[1]) : '';
  const params = m ? new URLSearchParams(paramsStr) : null;
  return { status: res.status, body, params, paramsStr };
}

test('AK-29 (a): valid login_hint is normalised and carried with pseudonym into the consent params', { skip }, async () => {
  const clientId = await createClient();
  const { status, params, paramsStr } = await authorize(clientId, { login_hint: 'Anna@Example.org', pseudonym: 'Anna' });
  assert.equal(status, 200);
  assert.ok(params, 'consent page embeds a params string');
  assert.equal(params.get('login_hint'), 'anna@example.org', 'login_hint normalised (trim + lower-case)');
  assert.equal(params.get('pseudonym'), 'Anna');
  assert.match(paramsStr, /login_hint=anna%40example\.org/, 'embedded params string carries the URL-encoded login_hint');
  assert.match(paramsStr, /pseudonym=Anna/, 'embedded params string carries the pseudonym');
  assert.equal(params.get('client_id'), clientId, 'existing params untouched');
});

test('AK-29 (b): a non-email login_hint (script payload) is dropped and never echoed', { skip }, async () => {
  const clientId = await createClient();
  const { status, body, params, paramsStr } = await authorize(clientId, { login_hint: '<script>alert(1)</script>' });
  assert.equal(status, 200, 'no error — silently omitted');
  assert.doesNotMatch(body, /<script>alert/, 'payload not echoed');
  assert.doesNotMatch(body, /alert\(1\)/, 'payload not echoed in any encoding');
  assert.doesNotMatch(paramsStr, /login_hint=/, 'no login_hint param at all');
  assert.equal(params.has('login_hint'), false);
  assert.equal(params.has('pseudonym'), false, 'absent pseudonym is not added as an empty param');
});

test('AK-29 (c): pseudonym is sanitized (forbidden chars stripped, max 32)', { skip }, async () => {
  const clientId = await createClient();
  const { status, body, params } = await authorize(clientId, { login_hint: 'anna@example.org', pseudonym: 'An<na>"\'/\\€!' + 'x'.repeat(40) });
  assert.equal(status, 200);
  assert.doesNotMatch(body, /<na>/);
  const p = params.get('pseudonym');
  assert.ok(p, 'pseudonym present');
  assert.match(p, /^[\w\-. äöüÄÖÜß]+$/u, 'only the safe charset survives');
  assert.ok(p.length <= 32, 'max 32 chars');
  assert.ok(p.startsWith('Anna'), `sanitized value starts with Anna: ${p}`);
});

test('AK-29 (d): a 300-char login_hint is dropped (limit 254)', { skip }, async () => {
  const clientId = await createClient();
  const long = 'a'.repeat(288) + '@example.org'; // 300 chars, syntactically an e-mail
  assert.equal(long.length, 300);
  const { status, body, params, paramsStr } = await authorize(clientId, { login_hint: long, pseudonym: 'Anna' });
  assert.equal(status, 200);
  assert.doesNotMatch(paramsStr, /login_hint=/);
  assert.doesNotMatch(body, /aaaaaaaaaa@example/, 'long address not echoed');
  assert.equal(params.has('login_hint'), false);
  assert.equal(params.get('pseudonym'), 'Anna', 'pseudonym still carried on its own');
});

test('AK-29: pseudonym that sanitizes to nothing is omitted, empty strings are not emitted', { skip }, async () => {
  const clientId = await createClient();
  const { status, params, paramsStr } = await authorize(clientId, { login_hint: '', pseudonym: '<>!?' });
  assert.equal(status, 200);
  assert.doesNotMatch(paramsStr, /login_hint=/);
  assert.doesNotMatch(paramsStr, /pseudonym=/);
  assert.equal(params.has('login_hint'), false);
  assert.equal(params.has('pseudonym'), false);
});

test('AK-30: consent page relogin() forwards login_hint/pseudonym and pre-fills #pseudoInput from params', { skip }, async () => {
  const clientId = await createClient();
  const { status, body } = await authorize(clientId, { login_hint: 'anna@example.org', pseudonym: 'Anna' });
  assert.equal(status, 200);
  const fn = body.match(/function relogin\(\)\{([\s\S]*?)\n\}/);
  assert.ok(fn, 'relogin() is defined in the consent page');
  assert.match(fn[1], /returnTo=/, 'relogin keeps returnTo');
  assert.match(fn[1], /login_hint/, 'relogin forwards login_hint');
  assert.match(fn[1], /pseudonym/, 'relogin forwards pseudonym');
  assert.match(fn[1], /encodeURIComponent/, 'values are URL-encoded');
  assert.match(body, /getElementById\('pseudoInput'\)[\s\S]{0,120}params\.get\('pseudonym'\)/, '#pseudoInput is pre-filled via DOM from params');
  assert.doesNotMatch(body, /id="pseudoInput"[^>]*value=/, 'pseudonym is NOT interpolated into the HTML value attribute');
});
