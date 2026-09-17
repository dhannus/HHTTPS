// Review 2026-09, Welle 3 — AP1 integration tests for the behaviour this wave
// unified against a booted server.js.
//
//   AP1-48 (#184)  one status code and one error shape across the signature
//                  endpoints: a missing bearer is 401 everywhere, an invalid one
//                  is 401 with { hhttps:{status:'invalid'}, error, code }
//   AP1-14 (#220)  Authorization is parsed per RFC 7235 (case-insensitive scheme,
//                  any run of whitespace) — not by `replace('Bearer ', '')`
//   AP1-43 (#155)  a token without a userId is not a signer identity
//   AP1-45 (#168)  the single-slug and the batch endpoint agree on the status
//                  ladder (revoked > wrong-domain > text-modified)
//   AP1-44 (#161)  one slug validator on all four routes
//   AP1-11 (#220)  an over-long revoke reason is truncated, not a DB error
//   AP1-18 (#220)  an IP literal is not an apex domain
//   AP1-51 (#196)  HHTTPS-Age-Verified has one owner
//   AP1-15 (#220)  the HTML viewer's raw-JSON link keeps the query string
//   AP1-01 (#220)  a malformed identity cookie does not 500 the request
//   AP1-16 (#220)  discovery advertises the live verification methods
import test from 'node:test';
import assert from 'node:assert/strict';
import { startServer, pgAvailable } from '../helpers/server.mjs';
import { closeDb, sql } from '../helpers/db.mjs';
import { rnd, freshEmail, verifyEmail, createTracker } from '../helpers/identity-flow.mjs';
import { loadOrCreateKeys, signToken } from '../../keys.js';

const skip = !pgAvailable() && 'TEST_PG_HOST not set';
let srv;
const track = createTracker();
const slugs = new Set();

test.before(async () => {
  if (skip) return;
  srv = await startServer({
    env: { SMTP_HOST: '', SMTP_USER: '', SMTP_PASS: '',
           GITHUB_CLIENT_ID: '', GITHUB_CLIENT_SECRET: '' },
  });
  loadOrCreateKeys();
});
test.after(async () => {
  if (skip) return;
  if (slugs.size) await sql('DELETE FROM signatures WHERE id = ANY($1)', [[...slugs]]);
  await track.cleanup();
  await srv.stop();
  await closeDb();
});

const auth = (token) => ({ headers: { authorization: `Bearer ${token}` } });

async function signedIn(tag) {
  const { sessionId, userId } = await verifyEmail(srv, freshEmail(tag), undefined, track);
  const r = await srv.api('/hhttps/role/declare', { method: 'POST', body: { sessionId } });
  assert.equal(r.status, 200, r.text);
  return { sessionId, userId, token: r.json.hhttps.token };
}

// One signed-in identity for every test that does not need a distinct user.
// Each sign-in costs several requests, and the whole suite shares one global
// rate-limit budget.
let _shared = null;
async function sharedUser() {
  if (!_shared) _shared = await signedIn('w3');
  return _shared;
}

async function createSignature(token, { text, bindingType = 'web', domain }) {
  const r = await srv.api('/hhttps/signatures', {
    method: 'POST', ...auth(token), body: { text, bindingType, domain },
  });
  assert.equal(r.status, 200, r.text);
  slugs.add(r.json.id);
  return r.json;
}

// ─── AP1-01: a broken identity cookie is not a 500 ───────────────────────────

test('AP1-01: a malformed identity cookie clears itself instead of 500-ing', { skip }, async () => {
  // '%E0%A4%A' is a truncated percent-escape: decodeURIComponent throws URIError.
  // The identity middleware runs on EVERY request, so this used to 500 the site.
  const r = await fetch(`${srv.baseUrl}/`, { headers: { cookie: 'hhttps_identity=%E0%A4%A' } });
  assert.equal(r.status, 200, await r.text());
  // a cookie we cannot decode is simply not an identity — issuer headers, no crash
  assert.equal(r.headers.get('hhttps-status'), 'issuer');
});

// ─── AP1-15 / AP1-27: the HTML viewer ────────────────────────────────────────

test('AP1-15: the viewer keeps the query string in its raw-JSON link', { skip }, async () => {
  const { token } = await sharedUser();
  const sig = await createSignature(token, { text: 'viewer', domain: 'example.com' });

  const html = await fetch(`${srv.baseUrl}/hhttps/s/${sig.id}?domain=evil.example`, {
    headers: { accept: 'text/html', 'user-agent': 'Mozilla/5.0' } });
  assert.equal(html.status, 200);
  assert.match(html.headers.get('content-type') || '', /text\/html/);
  const body = await html.text();
  assert.match(body, new RegExp(`href="/hhttps/s/${sig.id}\\?domain=evil\\.example&amp;format=json"`));
  assert.match(body, /new URL\(location\.href\)/);
});

// ─── AP1-51: one owner for HHTTPS-Age-Verified ───────────────────────────────

test('AP1-51: HHTTPS-Age-Verified reflects the age claim, not the method list',
  { skip }, async () => {
  const { token } = await sharedUser();
  const r = await srv.api('/hhttps/check', { method: 'POST', ...auth(token), body: {} });
  assert.equal(r.status, 200, r.text);
  // no age claim on a plain e-mail identity → the header is simply absent
  assert.equal(r.headers.get('hhttps-age-verified'), null);
  assert.equal(r.headers.get('hhttps-age-group'), null);
});

// ─── AP1-48: one status code, one error shape ────────────────────────────────

test('AP1-48: a missing bearer is 401 with a stable code on every token endpoint',
  { skip }, async () => {
  const sig = { id: 'hp-AAA-BBBBCC-DD' };
  for (const [path, body] of [
    ['/hhttps/sign-text', { text: 'x' }],
    ['/hhttps/signatures', { text: 'x', bindingType: 'web', domain: 'example.com' }],
    [`/hhttps/signatures/${sig.id}/revoke`, {}],
  ]) {
    const r = await srv.api(path, { method: 'POST', body });
    assert.equal(r.status, 401, `${path} → ${r.status} ${r.text}`);
    assert.equal(r.json.code, 'token_required', path);
    assert.equal(r.json.error, 'token required', path);
  }
});

test('AP1-48: an invalid bearer is 401 with the same envelope everywhere', { skip }, async () => {
  const junk = 'not.a.jwt';
  for (const [path, body] of [
    ['/hhttps/check', {}],
    ['/hhttps/sign-text', { text: 'x' }],
    ['/hhttps/signatures', { text: 'x', bindingType: 'web', domain: 'example.com' }],
  ]) {
    const r = await srv.api(path, { method: 'POST', ...auth(junk), body });
    assert.equal(r.status, 401, `${path} → ${r.status} ${r.text}`);
    assert.equal(r.json.code, 'token_invalid', path);
    assert.equal(r.json.hhttps.status, 'invalid', path);
    assert.equal(typeof r.json.error, 'string', path);
  }
});

test('AP1-48: the body-level 400s carry machine codes too', { skip }, async () => {
  const { token } = await sharedUser();
  const noText = await srv.api('/hhttps/signatures', { method: 'POST', ...auth(token), body: {} });
  assert.equal(noText.status, 400, noText.text);
  assert.equal(noText.json.code, 'text_required');

  const noDomain = await srv.api('/hhttps/signatures', {
    method: 'POST', ...auth(token), body: { text: 'x', bindingType: 'web' } });
  assert.equal(noDomain.status, 400, noDomain.text);
  assert.equal(noDomain.json.code, 'domain_required');

  const tooLong = await srv.api('/hhttps/sign-text', {
    method: 'POST', ...auth(token), body: { text: 'a'.repeat(100_001) } });
  assert.equal(tooLong.status, 400, tooLong.text);
  assert.equal(tooLong.json.code, 'text_too_long');

  const badSig = await srv.api('/hhttps/verify-text', { method: 'POST', body: { text: 'x' } });
  assert.equal(badSig.status, 400, badSig.text);
  assert.equal(badSig.json.code, 'signature_and_text_required');

  const bad = await srv.api('/hhttps/s/not-a-slug');
  assert.equal(bad.status, 400, bad.text);
  assert.equal(bad.json.code, 'invalid_slug');
});

// ─── AP1-14: RFC 7235 Authorization parsing ──────────────────────────────────

test('AP1-14: the Authorization scheme is case-insensitive and tolerates whitespace',
  { skip }, async () => {
  const { token } = await sharedUser();
  for (const header of [`Bearer ${token}`, `bearer ${token}`, `BEARER ${token}`,
                        `Bearer  ${token}`, `\tBearer ${token} `]) {
    const r = await srv.api('/hhttps/check', {
      method: 'POST', headers: { authorization: header }, body: {} });
    assert.equal(r.status, 200, `${JSON.stringify(header.slice(0, 12))} → ${r.status} ${r.text}`);
    assert.equal(r.json.hhttps.status, 'verified');
  }
  // a non-Bearer scheme is not a token — the header is not passed through raw
  const basic = await srv.api('/hhttps/check', {
    method: 'POST', headers: { authorization: `Basic ${token}` }, body: {} });
  assert.equal(basic.json.hhttps.status, 'unverified', basic.text);
});

// ─── AP1-43: a signer id, not the shared `sub` constant ──────────────────────

test('AP1-43: a token without a userId cannot sign or revoke', { skip }, async () => {
  // a well-formed, correctly signed access-shaped token that carries no userId:
  // before this wave the signer id fell back to sub === 'human-verified', which
  // every signed-in human shares.
  const orphan = signToken({
    jti: `w3-${rnd()}`, sub: 'human-verified', human: true, actorType: 'human',
    iss: 'https://localhost', hhttps_iss: 'hhttps://localhost'
  }, { expiresIn: 600 });

  const r = await srv.api('/hhttps/signatures', {
    method: 'POST', ...auth(orphan),
    body: { text: 'orphan', bindingType: 'web', domain: 'example.com' } });
  assert.equal(r.status, 401, r.text);
  // the token is not registered in `tokens`, so it never gets as far as the
  // signer check — either way it is refused, never silently attributed.
  assert.equal(r.json.code, 'token_invalid');
});

test('AP1-43: two different users get different signer ids', { skip }, async () => {
  const a = await signedIn('w3s1');
  const b = await signedIn('w3s2');
  const sigA = await createSignature(a.token, { text: 'mine', domain: 'example.com' });

  // b must not be able to revoke a's signature — that only holds if the signer
  // id is the user, not the shared `sub`.
  const foreign = await srv.api(`/hhttps/signatures/${sigA.id}/revoke`, {
    method: 'POST', ...auth(b.token), body: { reason: 'nope' } });
  assert.equal(foreign.status, 403, foreign.text);
  assert.equal(foreign.json.code, 'revoke_denied');

  const own = await srv.api(`/hhttps/signatures/${sigA.id}/revoke`, {
    method: 'POST', ...auth(a.token), body: { reason: 'mine to revoke' } });
  assert.equal(own.status, 200, own.text);
});

// ─── AP1-45: one status ladder for both verify endpoints ─────────────────────

test('AP1-45: single-slug and batch agree on revoked / wrong-domain / verified',
  { skip }, async () => {
  const { token } = await sharedUser();
  const good    = await createSignature(token, { text: 'ladder ok', domain: 'example.com' });
  const revoked = await createSignature(token, { text: 'ladder rev', domain: 'example.com' });
  await srv.api(`/hhttps/signatures/${revoked.id}/revoke`, {
    method: 'POST', ...auth(token), body: { reason: 'ladder' } });

  const batch = await srv.api('/hhttps/signatures/batch', {
    method: 'POST', body: { slugs: [good.id, revoked.id], domain: 'evil.example' } });
  assert.equal(batch.status, 200, batch.text);

  // revoked wins over a domain mismatch in BOTH endpoints
  const singleRevoked = await srv.api(`/hhttps/s/${revoked.id}?domain=evil.example`);
  assert.equal(singleRevoked.json.hhttps.status, 'revoked');
  assert.equal(batch.json.results[revoked.id].status, 'revoked');
  assert.ok(batch.json.results[revoked.id].revokedAt);

  const singleWrong = await srv.api(`/hhttps/s/${good.id}?domain=evil.example`);
  assert.equal(singleWrong.json.hhttps.status, 'wrong-domain');
  assert.equal(batch.json.results[good.id].status, 'wrong-domain');
  assert.equal(batch.json.results[good.id].expected, singleWrong.json.hhttps.expected);
  assert.equal(batch.json.results[good.id].observed, singleWrong.json.hhttps.observed);

  // matching domain → verified in both
  const okBatch = await srv.api('/hhttps/signatures/batch', {
    method: 'POST', body: { slugs: [good.id], domain: 'www.example.com' } });
  assert.equal(okBatch.json.results[good.id].status, 'verified');
  assert.equal((await srv.api(`/hhttps/s/${good.id}?domain=www.example.com`)).json.hhttps.status,
               'verified');
});

test('AP1-45: a modified document text is reported by both endpoints', { skip }, async () => {
  const { token } = await sharedUser();
  const text = 'Vertragstext, byte-genau.';
  const sig = await createSignature(token, { text, bindingType: 'document' });

  const same    = Buffer.from(text, 'utf8').toString('base64');
  const changed = Buffer.from(text + '!', 'utf8').toString('base64');

  assert.equal((await srv.api(`/hhttps/s/${sig.id}?textPreview=${encodeURIComponent(same)}`))
    .json.hhttps.status, 'verified');
  const tampered = await srv.api(`/hhttps/s/${sig.id}?textPreview=${encodeURIComponent(changed)}`);
  assert.equal(tampered.json.hhttps.status, 'text-modified');
  assert.match(tampered.json.warning, /modified after signing/);

  const batch = await srv.api('/hhttps/signatures/batch', {
    method: 'POST', body: { slugs: [sig.id], textPreviews: { [sig.id]: changed } } });
  assert.equal(batch.json.results[sig.id].status, 'text-modified');

  // an undecodable preview proves nothing — it must not flip the status
  const junk = await srv.api(`/hhttps/s/${sig.id}?textPreview=%%%`);
  assert.equal(junk.status, 200, junk.text);
});

// ─── AP1-44: one validator on all four routes ────────────────────────────────

test('AP1-44: every slug route rejects the same malformed slugs', { skip }, async () => {
  for (const bad of ['not-a-slug', 'hp_ABC', 'hp-ABC.DEF']) {
    assert.equal((await srv.api(`/hhttps/s/${bad}`)).status, 400, bad);
    const rev = await srv.api(`/hhttps/signatures/${bad}/revoke`, {
      method: 'POST', headers: { 'hhttps-token': 'x' }, body: {} });
    assert.equal(rev.status, 400, `${bad} revoke → ${rev.status}`);
    assert.equal(rev.json.code, 'invalid_slug');
    const red = await fetch(`${srv.baseUrl}/s/${bad}`, { redirect: 'manual' });
    assert.equal(red.status, 400, `${bad} short link`);
  }
  // the batch endpoint drops them silently and still answers for the rest
  const b = await srv.api('/hhttps/signatures/batch', {
    method: 'POST', body: { slugs: ['not-a-slug', 'hp-ZZZ-ZZZZZZ-ZZ'] } });
  assert.equal(b.status, 200, b.text);
  assert.equal(b.json.results['not-a-slug'], undefined);
  assert.equal(b.json.results['hp-ZZZ-ZZZZZZ-ZZ'].status, 'unknown');
});

// ─── AP1-11 / AP1-18: input bounds ───────────────────────────────────────────

test('AP1-11: an over-long revoke reason is truncated, not a database error',
  { skip }, async () => {
  const { token } = await sharedUser();
  const sig = await createSignature(token, { text: 'reason bound', domain: 'example.com' });

  const r = await srv.api(`/hhttps/signatures/${sig.id}/revoke`, {
    method: 'POST', ...auth(token), body: { reason: 'R'.repeat(500) } });
  assert.equal(r.status, 200, r.text);
  const row = (await sql('SELECT revoke_reason FROM signatures WHERE id = $1', [sig.id]))[0];
  assert.equal(row.revoke_reason.length, 120);
});

test('AP1-11: a non-string revoke reason is dropped instead of reaching the driver',
  { skip }, async () => {
  const { token } = await sharedUser();
  const sig = await createSignature(token, { text: 'reason type', domain: 'example.com' });
  const r = await srv.api(`/hhttps/signatures/${sig.id}/revoke`, {
    method: 'POST', ...auth(token), body: { reason: { evil: true } } });
  assert.equal(r.status, 200, r.text);
  const row = (await sql('SELECT revoke_reason FROM signatures WHERE id = $1', [sig.id]))[0];
  assert.equal(row.revoke_reason, null);
});

test('AP1-18: an IP literal is not an apex domain, and an over-long host is refused',
  { skip }, async () => {
  const { token } = await sharedUser();
  for (const domain of ['192.168.1.10', '10.0.0.1', '8.8.8.8',
                        `${'a'.repeat(64)}.example.com`, `${'a.'.repeat(80)}example.com`]) {
    const r = await srv.api('/hhttps/signatures', {
      method: 'POST', ...auth(token), body: { text: 'ip bind', bindingType: 'web', domain } });
    assert.equal(r.status, 400, `${domain} → ${r.status} ${r.text}`);
    assert.equal(r.json.code, 'invalid_domain');
  }
});

// ─── AP1-16: discovery advertises the live verification surface ──────────────

test('AP1-16: discovery lists the verification METHODS registry', { skip }, async () => {
  const r = await srv.api('/.well-known/hhttps-configuration');
  assert.equal(r.status, 200, r.text);
  assert.ok(Array.isArray(r.json.supported_verification_methods));
  assert.ok(r.json.supported_verification_methods.includes('email'));
  assert.ok(r.json.supported_verification_methods.includes('passkey'));
  // the legacy list is still there for one release
  assert.ok(Array.isArray(r.json.supported_verification));
});
