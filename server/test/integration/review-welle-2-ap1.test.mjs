// Review 2026-09, Welle 2 — AP1 integration tests against a booted server.js.
//
//   AP1-09  the core endpoints had no test at all: /hhttps/check, sign-text /
//           verify-text, the slug signature lifecycle and the batch endpoint
//   AP1-23  refresh tokens are not identity bearers for check / sign-text /
//           signatures / signature revoke
//   AP1-03  an expired-but-authentic text signature reports `expired`, not 401
//   AP1-02  async handlers answer instead of hanging; the batch filter tolerates
//           non-string entries
//   AP1-05  every HHTTPS-* header the server emits is CORS-exposed
//   AP1-17  the identity cookie is a positive list (human-verified + jti) and is
//           checked against the revocation list
//   AP1-25  the CSP pins the two unpkg bundles instead of the whole host
//   AP1-26  the first-seen lock is only recorded by the bound domain
//   AP1-32  /hhttps/info is rate-limited and cached
//   AP1-33  check_calls is accumulated in-process and flushed
//   AP1-34/35  cleanup_expired() retires revoked_tokens and webhook_deliveries
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import pg from 'pg';
import { startServer, pgAvailable } from '../helpers/server.mjs';
import { closeDb, sql, TEST_DB } from '../helpers/db.mjs';
import { rnd, freshEmail, verifyEmail, decodeJwtPayload, createTracker } from '../helpers/identity-flow.mjs';
import { migrate } from '../../scripts/migrate.js';
import { loadOrCreateKeys, signToken } from '../../keys.js';

const skip = !pgAvailable() && 'TEST_PG_HOST not set';
let srv;
const track = createTracker();
const slugs = new Set();
const revokedJtis = new Set();

test.before(async () => {
  if (skip) return;
  srv = await startServer({
    env: {
      SMTP_HOST: '', SMTP_USER: '', SMTP_PASS: '',
      GITHUB_CLIENT_ID: '', GITHUB_CLIENT_SECRET: '',
      STATS_FLUSH_MS: '250',   // AP1-33: flush fast enough to assert on
    },
  });
  loadOrCreateKeys();          // same keys/ directory the child server uses
});
test.after(async () => {
  if (skip) return;
  if (slugs.size) await sql('DELETE FROM signatures WHERE id = ANY($1)', [[...slugs]]);
  if (revokedJtis.size) await sql('DELETE FROM revoked_tokens WHERE jti = ANY($1)', [[...revokedJtis]]);
  await track.cleanup();
  await srv.stop();
  await closeDb();
});

const auth = (token) => ({ headers: { authorization: `Bearer ${token}` } });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** e-mail-verified session with a declared role → { token, refreshToken, … }. */
async function signedIn(tag) {
  const { sessionId, userId } = await verifyEmail(srv, freshEmail(tag), undefined, track);
  const r = await srv.api('/hhttps/role/declare', { method: 'POST', body: { sessionId } });
  assert.equal(r.status, 200, r.text);
  return { sessionId, userId, token: r.json.hhttps.token, refreshToken: r.json.hhttps.refreshToken };
}

async function createSignature(token, { text, bindingType = 'web', domain }) {
  const r = await srv.api('/hhttps/signatures', {
    method: 'POST', ...auth(token), body: { text, bindingType, domain },
  });
  assert.equal(r.status, 200, r.text);
  slugs.add(r.json.id);
  return r.json;
}

// ─── AP1-09 / AP1-23: /hhttps/check ──────────────────────────────────────────
test('AP1-09: /hhttps/check answers unverified without a token and verified with one', { skip }, async () => {
  const anon = await srv.api('/hhttps/check', { method: 'POST', body: {} });
  assert.equal(anon.status, 200, anon.text);
  assert.equal(anon.json.hhttps.status, 'unverified');
  assert.equal(anon.json.hhttps.human, false);
  assert.equal(anon.headers.get('hhttps-status'), 'unverified');

  const { token } = await signedIn('w2c');
  const ok = await srv.api('/hhttps/check', { method: 'POST', ...auth(token) });
  assert.equal(ok.status, 200, ok.text);
  assert.equal(ok.json.hhttps.status, 'verified');
  assert.equal(ok.json.hhttps.human, true);
  assert.equal(ok.json.hhttps.actorType, 'human');
  assert.ok(ok.json.hhttps.verifiedMethods.includes('email'), JSON.stringify(ok.json.hhttps.verifiedMethods));
  assert.equal(ok.headers.get('hhttps-status'), 'verified');
  assert.match(String(ok.headers.get('hhttps-verified-methods')), /\bemail\b/);
  assert.equal(ok.headers.get('hhttps-email-verified'), 'true');

  const junk = await srv.api('/hhttps/check', { method: 'POST', ...auth('not.a.jwt') });
  assert.equal(junk.status, 401, junk.text);
  assert.equal(junk.json.hhttps.status, 'invalid');
  assert.equal(junk.headers.get('hhttps-status'), 'invalid');
});

test('AP1-23: a refresh token is refused by check, sign-text, signatures and revoke', { skip }, async () => {
  const { token, refreshToken } = await signedIn('w2r');
  assert.equal(decodeJwtPayload(refreshToken).sub, 'refresh');

  const sig = await createSignature(token, { text: 'refresh guard', domain: 'example.com' });

  for (const [path, body] of [
    ['/hhttps/check', {}],
    ['/hhttps/sign-text', { text: 'hello' }],
    ['/hhttps/signatures', { text: 'hello', bindingType: 'web', domain: 'example.com' }],
    [`/hhttps/signatures/${sig.id}/revoke`, { reason: 'test' }],
  ]) {
    const r = await srv.api(path, { method: 'POST', ...auth(refreshToken), body });
    assert.equal(r.status, 401, `${path} → ${r.status} ${r.text}`);
    assert.match(String(r.json.error), /refresh/i, `${path}: ${r.json.error}`);
  }

  // the signature is still there — the refused revoke changed nothing
  const still = await srv.api(`/hhttps/s/${sig.id}`);
  assert.equal(still.json.hhttps.status, 'verified');
});

// ─── AP1-09 / AP1-03: sign-text and verify-text ──────────────────────────────
test('AP1-09: sign-text → verify-text round trip, and a modified text is detected', { skip }, async () => {
  const { token } = await signedIn('w2t');
  const text = 'Ich bestätige diesen Vertrag.';

  const signed = await srv.api('/hhttps/sign-text', { method: 'POST', ...auth(token), body: { text } });
  assert.equal(signed.status, 200, signed.text);
  const signature = signed.json.signature;
  assert.equal(decodeJwtPayload(signature).sub, 'text-signature');

  const ok = await srv.api('/hhttps/verify-text', { method: 'POST', body: { signature, text } });
  assert.equal(ok.status, 200, ok.text);
  assert.equal(ok.json.hhttps.status, 'verified');
  assert.equal(ok.json.match, true);

  const tampered = await srv.api('/hhttps/verify-text', { method: 'POST', body: { signature, text: text + ' NICHT.' } });
  assert.equal(tampered.status, 200, tampered.text);
  assert.equal(tampered.json.hhttps.status, 'invalid');
  assert.equal(tampered.json.hhttps.reason, 'text-modified');
  assert.equal(tampered.json.match, false);

  // a non-text-signature JWT is rejected as such, a broken one as invalid
  const wrongSub = await srv.api('/hhttps/verify-text', { method: 'POST', body: { signature: token, text } });
  assert.equal(wrongSub.status, 400, wrongSub.text);
  const broken = await srv.api('/hhttps/verify-text', { method: 'POST', body: { signature: 'a.b.c', text } });
  assert.equal(broken.status, 401, broken.text);
  assert.equal(broken.json.hhttps.status, 'invalid');

  const missing = await srv.api('/hhttps/verify-text', { method: 'POST', body: { text } });
  assert.equal(missing.status, 400, missing.text);
});

test('AP1-03: an expired but authentic text signature reports `expired`, not 401 invalid', { skip }, async () => {
  const text = 'Diese Zusage galt bis gestern.';
  const textHash = crypto.createHash('sha256').update(text, 'utf8').digest('hex');
  const now = Math.floor(Date.now() / 1000);

  // Signed with the server's own active key — authentic, but long expired.
  const expired = signToken({
    sub: 'text-signature', tokenJti: `w2-${rnd()}`, textHash,
    role: 'citizen', roleLevel: 'self-declared', trustScore: 20,
    iat: now - 7200, exp: now - 60,
  });

  const r = await srv.api('/hhttps/verify-text', { method: 'POST', body: { signature: expired, text } });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.json.hhttps.status, 'expired');
  assert.equal(r.json.match, true);

  // an expired signature over a MODIFIED text still reports the tampering first
  const t = await srv.api('/hhttps/verify-text', { method: 'POST', body: { signature: expired, text: text + '!' } });
  assert.equal(t.json.hhttps.status, 'invalid');
  assert.equal(t.json.hhttps.reason, 'text-modified');

  // a text signature without any exp is treated as expired, never as valid
  const noExp = signToken({ sub: 'text-signature', tokenJti: `w2-${rnd()}`, textHash, role: 'citizen' });
  const n = await srv.api('/hhttps/verify-text', { method: 'POST', body: { signature: noExp, text } });
  assert.equal(n.status, 200, n.text);
  assert.equal(n.json.hhttps.status, 'expired');
});

// ─── AP1-09 / AP1-26: slug signature lifecycle ───────────────────────────────
test('AP1-09: a slug signature is created, publicly verifiable, domain-bound and revocable', { skip }, async () => {
  const { token } = await signedIn('w2s');
  const sig = await createSignature(token, { text: 'Signiert auf meiner Seite.', domain: 'https://www.example.com/a/b' });
  assert.match(sig.id, /^hp-[A-Z0-9-]+$/);
  assert.equal(sig.marker, `#hhttps:s:${sig.id}`);
  assert.equal(sig.binding.type, 'web');
  assert.equal(sig.binding.domain, 'example.com', 'apex-normalised');
  // a v0.5 token carries no role — the snapshot falls back instead of hitting
  // the NOT NULL constraint (which surfaced as a bogus 401 before)
  assert.equal(sig.role.id, 'citizen');

  const pub = await srv.api(`/hhttps/s/${sig.id}`);
  assert.equal(pub.status, 200, pub.text);
  assert.equal(pub.json.hhttps.status, 'verified');
  assert.equal(pub.json.binding.domain, 'example.com');

  const wrong = await srv.api(`/hhttps/s/${sig.id}?domain=evil.example`);
  assert.equal(wrong.json.hhttps.status, 'wrong-domain');
  assert.equal(wrong.json.hhttps.expected, 'example.com');

  const bad = await srv.api('/hhttps/s/not-a-slug');
  assert.equal(bad.status, 400, bad.text);
  const unknown = await srv.api(`/hhttps/s/hp-${rnd().toUpperCase()}`);
  assert.equal(unknown.status, 404, unknown.text);
  assert.equal(unknown.json.hhttps.status, 'unknown');

  // short link
  const red = await fetch(`${srv.baseUrl}/s/${sig.id}`, { redirect: 'manual' });
  assert.equal(red.status, 302);
  assert.equal(red.headers.get('location'), `/hhttps/s/${sig.id}`);

  // revoke: only the signer, and only once
  const foreign = await signedIn('w2f');
  const nope = await srv.api(`/hhttps/signatures/${sig.id}/revoke`, {
    method: 'POST', ...auth(foreign.token), body: { reason: 'nope' } });
  assert.equal(nope.status, 403, nope.text);

  const rev = await srv.api(`/hhttps/signatures/${sig.id}/revoke`, {
    method: 'POST', ...auth(token), body: { reason: 'tested' } });
  assert.equal(rev.status, 200, rev.text);
  const after = await srv.api(`/hhttps/s/${sig.id}`);
  assert.equal(after.json.hhttps.status, 'revoked');
  const twice = await srv.api(`/hhttps/signatures/${sig.id}/revoke`, {
    method: 'POST', ...auth(token), body: {} });
  assert.equal(twice.status, 403, twice.text);
});

test('AP1-26: only the bound domain sets the first-seen lock', { skip }, async () => {
  const { token } = await signedIn('w2fs');
  const sig = await createSignature(token, { text: 'first seen lock', domain: 'example.org' });

  // a stranger claiming a foreign domain must not stamp the signature
  const stranger = await srv.api(`/hhttps/s/${sig.id}?domain=attacker.example`);
  assert.equal(stranger.json.hhttps.status, 'wrong-domain');
  assert.equal(stranger.json.firstSeen, null);
  let row = (await sql('SELECT first_seen_at, first_seen_domain FROM signatures WHERE id = $1', [sig.id]))[0];
  assert.equal(row.first_seen_at, null, 'no lock from a foreign domain');

  // the bound domain does
  const home = await srv.api(`/hhttps/s/${sig.id}?domain=www.example.org`);
  assert.equal(home.json.hhttps.status, 'verified');
  row = (await sql('SELECT first_seen_at, first_seen_domain FROM signatures WHERE id = $1', [sig.id]))[0];
  assert.ok(row.first_seen_at, 'lock recorded for the bound domain');
  assert.equal(row.first_seen_domain, 'example.org');

  // an e-mail binding has no domain to confirm — it stays unlocked
  const mail = await createSignature(token, { text: 'mail sig', bindingType: 'email' });
  await srv.api(`/hhttps/s/${mail.id}?domain=attacker.example`);
  const mrow = (await sql('SELECT first_seen_at FROM signatures WHERE id = $1', [mail.id]))[0];
  assert.equal(mrow.first_seen_at, null, 'unbound signature is never stamped');
});

// ─── AP1-02: batch endpoint ──────────────────────────────────────────────────
test('AP1-02: /hhttps/signatures/batch ignores non-string entries and answers for every slug', { skip }, async () => {
  const { token } = await signedIn('w2b');
  const sig = await createSignature(token, { text: 'batch me', domain: 'example.com' });
  const ghost = `hp-${rnd().toUpperCase()}`;

  const r = await srv.api('/hhttps/signatures/batch', {
    method: 'POST',
    body: { slugs: [sig.id, ghost, 42, null, { id: sig.id }, ['hp-X'], 'not-a-slug'], domain: 'example.com' },
  });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.json.results[sig.id].status, 'verified');
  assert.equal(r.json.results[ghost].status, 'unknown');
  assert.equal(Object.keys(r.json.results).length, 2, 'junk entries dropped, not crashed on');

  const wrongDomain = await srv.api('/hhttps/signatures/batch', {
    method: 'POST', body: { slugs: [sig.id], domain: 'evil.example' } });
  assert.equal(wrongDomain.json.results[sig.id].status, 'wrong-domain');

  const empty = await srv.api('/hhttps/signatures/batch', { method: 'POST', body: { slugs: [] } });
  assert.equal(empty.status, 400, empty.text);
  const tooMany = await srv.api('/hhttps/signatures/batch', {
    method: 'POST', body: { slugs: Array(101).fill(sig.id) } });
  assert.equal(tooMany.status, 400, tooMany.text);
});

// ─── AP1-05 / AP1-25: CORS + CSP ─────────────────────────────────────────────
test('AP1-05: every HHTTPS header the server can emit is listed in Access-Control-Expose-Headers', { skip }, async () => {
  const r = await srv.api('/hhttps/info', { headers: { origin: 'https://partner.example' } });
  const exposed = new Set(String(r.headers.get('access-control-expose-headers') || '')
    .split(',').map((s) => s.trim().toLowerCase()).filter(Boolean));
  for (const h of [
    'hhttps-protocol-version', 'hhttps-status', 'hhttps-human', 'hhttps-trust-score',
    'hhttps-verified-methods', 'hhttps-ral', 'hhttps-role-isco08',
    'hhttps-email-verified', 'hhttps-passkey-verified', 'hhttps-domain-verified',
    'hhttps-domain', 'hhttps-github-verified', 'hhttps-eudi-verified', 'hhttps-age-verified',
  ]) {
    assert.ok(exposed.has(h), `${h} not exposed (got: ${[...exposed].join(', ')})`);
  }
  assert.equal(exposed.size, [...exposed].length, 'no duplicates');
});

test('AP1-25: the CSP pins the two unpkg bundles instead of the whole host', { skip }, async () => {
  const r = await srv.api('/hhttps/info');
  const csp = String(r.headers.get('content-security-policy') || '');
  const scriptSrc = csp.split(';').map((s) => s.trim()).find((s) => s.startsWith('script-src '));
  assert.ok(scriptSrc, csp);
  assert.equal(/(^|\s)unpkg\.com(\s|$)/.test(scriptSrc), false, `bare unpkg.com still allowed: ${scriptSrc}`);
  assert.match(scriptSrc, /https:\/\/unpkg\.com\/qrcode-generator@1\.4\.4\/qrcode\.js/);
  assert.match(scriptSrc, /https:\/\/unpkg\.com\/@simplewebauthn\/browser@9\.0\.1\//);
});

// ─── AP1-17: identity cookie ─────────────────────────────────────────────────
test('AP1-17: only a human-verified access token is accepted as identity cookie', { skip }, async () => {
  const { token, refreshToken } = await signedIn('w2ck');
  const withCookie = (value) => srv.api('/.well-known/jwks.json', { headers: { cookie: `hhttps_identity=${value}` } });

  const good = await withCookie(token);
  assert.equal(good.headers.get('hhttps-status'), 'verified');
  assert.equal(good.headers.get('hhttps-human'), 'true');

  // a text signature is authentic but NOT an identity
  const textSig = signToken({ sub: 'text-signature', tokenJti: 'x', textHash: 'y' }, { expiresIn: 600 });
  // …and neither is a refresh token, nor a token without a jti
  const noJti = signToken({ sub: 'human-verified', role: 'citizen' }, { expiresIn: 600 });

  for (const [name, value] of [['text-signature', textSig], ['refresh', refreshToken], ['no jti', noJti], ['garbage', 'a.b.c']]) {
    const r = await withCookie(value);
    assert.notEqual(r.headers.get('hhttps-status'), 'verified', `${name} accepted as identity`);
    const setCookie = (r.headers.getSetCookie?.() || []).join('|');
    assert.match(setCookie, /hhttps_identity=/, `${name}: cookie not cleared`);
  }
});

test('AP1-17: a revoked access token is no longer accepted as identity cookie', { skip }, async () => {
  const { token } = await signedIn('w2rv');
  const rev = await srv.api('/hhttps/revoke', { method: 'POST', body: { token } });
  assert.equal(rev.status, 200, rev.text);
  revokedJtis.add(rev.json.jti);

  const r = await srv.api('/.well-known/jwks.json', { headers: { cookie: `hhttps_identity=${token}` } });
  assert.notEqual(r.headers.get('hhttps-status'), 'verified');
  assert.match((r.headers.getSetCookie?.() || []).join('|'), /hhttps_identity=/);
});

// ─── AP1-32 / AP1-33: /hhttps/info and the stats accumulator ─────────────────
test('AP1-32: /hhttps/info is rate-limited, cached and still answers the full payload', { skip }, async () => {
  const r = await srv.api('/hhttps/info');
  assert.equal(r.status, 200, r.text);
  assert.equal(r.headers.get('cache-control'), 'public, max-age=30');
  const vary = String(r.headers.get('vary') || '').toLowerCase();
  assert.match(vary, /accept/, 'a negotiated response must not be cached without Vary');
  assert.match(vary, /user-agent/, 'sendJson also negotiates on User-Agent');
  assert.ok(r.headers.get('ratelimit-limit') || r.headers.get('ratelimit'),
    'no standard rate-limit header — /hhttps/info is still exempt');
  assert.equal(r.json.version, '0.5.0');
  assert.equal(typeof r.json.stats, 'object');

  // second call inside the TTL is served from the counter cache (same numbers)
  const again = await srv.api('/hhttps/info');
  assert.deepEqual(again.json.stats, r.json.stats);
});

test('AP1-33: check_calls is accumulated in-process and flushed to the stats row', { skip }, async () => {
  const read = async () => Number((await sql(`SELECT value FROM stats WHERE metric = 'check_calls'`))[0]?.value ?? 0);
  const before = await read();
  for (let i = 0; i < 3; i++) await srv.api('/hhttps/check', { method: 'POST', body: {} });

  let after = before;
  for (let i = 0; i < 40 && after < before + 3; i++) { await sleep(100); after = await read(); }
  assert.ok(after >= before + 3, `check_calls ${before} → ${after} (flush did not run)`);
});

// ─── AP1-34 / AP1-35: cleanup retention ──────────────────────────────────────
test('AP1-34/35: cleanup_expired() retires old revoked_tokens and webhook_deliveries', { skip }, async () => {
  const dbName = `hhttps_w2ap1_${rnd()}`;
  try { await sql(`CREATE DATABASE ${dbName}`); }
  catch (e) { if (/permission/i.test(e.message)) return; throw e; }
  const client = new pg.Client({ ...TEST_DB, database: dbName });
  try {
    await client.connect();
    await migrate({ client, log: { log() {} } });

    const cols = (await client.query(
      `SELECT * FROM cleanup_expired()`)).fields.map((f) => f.name);
    assert.ok(cols.includes('deleted_revoked'), `cleanup_expired columns: ${cols.join(', ')}`);
    assert.ok(cols.includes('deleted_webhook_deliveries'), `cleanup_expired columns: ${cols.join(', ')}`);

    await client.query(
      `INSERT INTO revoked_tokens (jti, revoked_at) VALUES ('old', NOW() - INTERVAL '9 days'), ('fresh', NOW())`);
    await client.query(
      `INSERT INTO webhook_deliveries (event, status, delivered_at)
       VALUES ('token.issued', 'success', NOW() - INTERVAL '31 days'), ('token.issued', 'success', NOW())`);

    const { rows } = await client.query(`SELECT * FROM cleanup_expired()`);
    assert.equal(Number(rows[0].deleted_revoked), 1);
    assert.equal(Number(rows[0].deleted_webhook_deliveries), 1);

    const left = await client.query(`SELECT jti FROM revoked_tokens`);
    assert.deepEqual(left.rows.map((r) => r.jti), ['fresh']);
    const deliveries = await client.query(`SELECT count(*)::int AS n FROM webhook_deliveries`);
    assert.equal(deliveries.rows[0].n, 1);
  } finally {
    await client.end().catch(() => {});
    await sql(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`).catch(() => {});
  }
});

// ─── AP1-08: the ESCO proxy ──────────────────────────────────────────────────
test('AP1-08: the ESCO proxy is rate-limited and always answers (timeout, never a hang)', { skip }, async () => {
  const short = await srv.api('/hhttps/esco/suggest?q=a');
  assert.equal(short.status, 200, short.text);
  assert.deepEqual(short.json.results, []);
  assert.ok(short.headers.get('ratelimit-limit') || short.headers.get('ratelimit'),
    'the ESCO proxy has no own rate limit');

  // Upstream may be unreachable from CI — either way the request must return
  // well inside the 4 s AbortSignal timeout plus overhead, never hang.
  const t0 = Date.now();
  const r = await srv.api(`/hhttps/esco/suggest?q=kraftfahrer${rnd()}`);
  assert.equal(r.status, 200, r.text);
  assert.ok(Array.isArray(r.json.results));
  assert.ok(Date.now() - t0 < 15_000, 'ESCO proxy did not return in time');
});
