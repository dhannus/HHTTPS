// Welle 3 / AP2 — the pure parts of the OAuth refactoring.
//
//   AP2-30 (#157)  validateScopes: one scope policy for /authorize + /approve
//   AP2-28 (#138)  the token endpoint is a dispatcher, one function per grant
//   AP2-29 (#147)  access/refresh JWT bodies come from shared builders
//   AP2-33 (#175)  every /hhttps/oauth/* route answers with RFC codes
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { validateScopes, SCOPES_KNOWN } from '../../oauth-params.js';

const here = dirname(fileURLToPath(import.meta.url));
const src = readFileSync(join(here, '../../server.js'), 'utf8');

const client = (allowed) => ({ allowed_scopes: allowed });

// ─── AP2-30 (#157): validateScopes ───────────────────────────────────────────

test('AP2-30: SCOPES_KNOWN is the single scope registry and is frozen', () => {
  assert.deepEqual([...SCOPES_KNOWN], ['openid', 'role', 'verification_method', 'age_group', 'email']);
  assert.ok(Object.isFrozen(SCOPES_KNOWN));
  // server.js no longer keeps a second copy.
  assert.doesNotMatch(src, /const SCOPES_KNOWN\s*=\s*new Set/, 'no local copy in server.js');
  assert.match(src, /scopes_supported:\s*\[\.\.\.SCOPES_KNOWN\]/, 'discovery derives from the registry');
});

test('AP2-30: a missing scope defaults to openid, exactly as both routes did', () => {
  for (const empty of [undefined, null, '']) {
    const r = validateScopes(empty, client(['openid']));
    assert.equal(r.ok, true, String(empty));
    assert.deepEqual(r.scopes, ['openid']);
  }
  // A whitespace-only `scope` is not "absent" — it parses to no scope at all
  // and therefore misses `openid`. Unchanged from `(scope || 'openid').split()`.
  const blank = validateScopes('   ', client(['openid']));
  assert.equal(blank.ok, false);
  assert.equal(blank.error, 'invalid_scope');
});

test('AP2-30: openid is mandatory', () => {
  const r = validateScopes('email role', client(['openid', 'email', 'role']));
  assert.equal(r.ok, false);
  assert.equal(r.error, 'invalid_scope');
  assert.match(r.description, /openid/);
});

test('AP2-30: unknown scopes are rejected before the client policy', () => {
  const r = validateScopes('openid does-not-exist', client(['openid']));
  assert.equal(r.ok, false);
  assert.equal(r.error, 'invalid_scope');
  assert.match(r.description, /Unknown scopes: does-not-exist/);
});

test('AP2-30: a scope the client may not request is denied (F-8/K-8)', () => {
  const r = validateScopes('openid email', client(['openid', 'role']));
  assert.equal(r.ok, false);
  assert.equal(r.error, 'invalid_scope');
  assert.match(r.description, /Platform may not request these scopes: email/);
});

test('AP2-30: a fully allowed request passes and returns the parsed, de-duplicated-by-whitespace list', () => {
  const r = validateScopes('  openid   role\temail ', client(['openid', 'role', 'email']));
  assert.equal(r.ok, true);
  assert.deepEqual(r.scopes, ['openid', 'role', 'email']);
});

test('AP2-30: a client without allowed_scopes gets nothing but a clean invalid_scope', () => {
  const r = validateScopes('openid', {});
  assert.equal(r.ok, false);
  assert.equal(r.error, 'invalid_scope');
});

test('AP2-30: both routes use validateScopes, neither re-implements the policy', () => {
  const authorize = src.slice(src.indexOf("app.get('/hhttps/oauth/authorize'"),
                              src.indexOf("app.post('/hhttps/oauth/approve'"));
  const approve = src.slice(src.indexOf("app.post('/hhttps/oauth/approve'"),
                            src.indexOf("app.post('/hhttps/oauth/token'"));
  for (const [name, route] of [['authorize', authorize], ['approve', approve]]) {
    assert.match(route, /validateScopes\(scope, client\)/, `${name} calls validateScopes`);
    assert.doesNotMatch(route, /SCOPES_KNOWN\.has/, `${name} has no inline scope filter`);
    assert.doesNotMatch(route, /includes\('openid'\)/, `${name} has no inline openid check`);
  }
});

// ─── AP2-28 (#138) / AP2-29 (#147): the token endpoint ───────────────────────

/** Source of one top-level function declaration. */
function fn(name) {
  const start = src.indexOf(`function ${name}(`);
  assert.ok(start > 0, `${name} is defined`);
  const end = src.indexOf('\n}\n', start);
  assert.ok(end > start, `${name} ends`);
  return src.slice(start, end);
}

test('AP2-28: handleTokenRequest is a dispatcher, not a 268-line handler', () => {
  const dispatcher = fn('handleTokenRequest');
  assert.ok(dispatcher.split('\n').length < 20, `dispatcher stays short (${dispatcher.split('\n').length} lines)`);
  assert.match(dispatcher, /handleRefreshGrant\(req, res\)/);
  assert.match(dispatcher, /handleCodeGrant\(req, res\)/);
  assert.match(dispatcher, /unsupported_grant_type/);
  // No grant is written out inline any more.
  assert.doesNotMatch(dispatcher, /authCodes\.claim/);
  assert.doesNotMatch(dispatcher, /refresh_tokens/);
});

test('AP2-28: each grant is its own function', () => {
  for (const name of ['handleRefreshGrant', 'handleCodeGrant']) {
    assert.match(src, new RegExp(`async function ${name}\\(req, res\\)`), `${name} exists`);
  }
  // AP2-28: `code` / `redirect_uri` / `code_verifier` are destructured in the
  // code grant only — they were dead weight in the refresh branch.
  const refresh = fn('handleRefreshGrant');
  assert.doesNotMatch(refresh, /code_verifier/, 'refresh grant does not touch code_verifier');
  assert.doesNotMatch(refresh, /redirect_uri/, 'refresh grant does not touch redirect_uri');
});

test('AP2-29: the access and refresh JWT bodies are built in exactly one place each', () => {
  assert.match(src, /function buildOAuthAccessClaims\(/);
  assert.match(src, /function buildOAuthRefreshClaims\(/);
  assert.match(src, /function ageClaims\(source\)/);
  assert.match(src, /function actorClaims\(source\)/);

  // Each builder is called exactly twice (once per grant) — nothing spells the
  // claims out a third time.
  assert.equal((src.match(/signToken\(buildOAuthAccessClaims\(\{/g) || []).length, 2);
  assert.equal((src.match(/signToken\(buildOAuthRefreshClaims\(\{/g) || []).length, 2);

  // Within the token endpoint the six hand-written age_group blocks are gone:
  // `age_verification_method` is only ever produced by ageClaims(), and the
  // bot claims only by actorClaims().
  const tokenSection = src.slice(src.indexOf('async function handleTokenRequest('),
                                 src.indexOf('// UserInfo endpoint'));
  const produced = tokenSection.match(/^\s*age_verification_method:/gm) || [];
  assert.equal(produced.length, 1, `age_verification_method is emitted once, found ${produced.length}`);
  const bot = tokenSection.match(/actor_type: 'bot', human: false/g) || [];
  assert.equal(bot.length, 1, `the bot claims are emitted once, found ${bot.length}`);
});

test('AP2-29/AP2-30: neither grant hashes a client secret on its own any more', () => {
  for (const name of ['handleRefreshGrant', 'handleCodeGrant']) {
    const body = fn(name);
    assert.match(body, /authenticateOAuthClient\(client_id, client_secret\)/, `${name} authenticates centrally`);
    assert.doesNotMatch(body, /client_secret_hash/, `${name} has no inline secret comparison`);
    assert.doesNotMatch(body, /createHash\('sha256'\)\.update\(client_secret\)/, `${name} does not hash the secret itself`);
  }
});

test('AP2-20: the client secret is compared in constant time', () => {
  const body = fn('authenticateOAuthClient');
  assert.match(body, /crypto\.timingSafeEqual\(/, 'timingSafeEqual is used');
  assert.match(body, /stored\.length !== expected\.length/, 'length is checked first');
  assert.doesNotMatch(body, /expected !== client\.client_secret_hash/, 'no plain string comparison left');
});

// ─── AP2-33 (#175): RFC error codes across the OAuth routes ──────────────────

test('AP2-33: no free-text error codes are left in the OAuth routes', () => {
  const oauth = src.slice(src.indexOf("app.get('/hhttps/oauth/authorize'"),
                          src.indexOf('function renderConsentPage('));
  for (const legacy of ["error: 'token required'", "error: 'unknown client'",
                        "error: 'redirect_uri mismatch'", "error: 'openid scope required'",
                        "error: 'unauthorized'", "error: 'token + client_id required'",
                        'error: e.message']) {
    assert.ok(!oauth.includes(legacy), `free-text error gone: ${legacy}`);
  }
  // Every JSON error in this block uses an RFC code.
  const RFC = new Set(['invalid_request', 'invalid_client', 'invalid_grant', 'invalid_scope',
                       'invalid_token', 'unsupported_grant_type', 'server_error', 'access_denied',
                       'tv.error', 'sv.error', 'v.error', 'errorCode']);
  for (const m of oauth.matchAll(/error:\s*'([a-z_]+)'/g)) {
    assert.ok(RFC.has(m[1]), `RFC 6749/6750 code: ${m[1]}`);
  }
});

test('AP2-33: /userinfo answers every rejected bearer token via userinfoInvalidToken (RFC 6750 §3)', () => {
  const route = src.slice(src.indexOf("app.get('/hhttps/oauth/userinfo'"),
                          src.indexOf('function userinfoInvalidToken('));
  assert.equal((route.match(/userinfoInvalidToken\(res,/g) || []).length, 3,
    'missing token, unverifiable token and non-access token all take the same exit');
  assert.doesNotMatch(route, /status\(403\)/, 'no 403 — RFC 6750 uses 401 for an invalid token');
  assert.match(fn('userinfoInvalidToken'), /WWW-Authenticate/);
});
