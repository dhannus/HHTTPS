// Review 2026-09, Welle 2 — AP3 (identity, session, e-mail, WebAuthn, GitHub).
//   AP3-03  malformed bodies answer instead of hanging (unhandled rejection)
//   AP3-04  /email/verify survives array/object query parameters
//   AP3-05  code / context / session TTL are aligned
//   AP3-08  a revoked token's identity cookie stops reporting `verified`
//   AP3-09  a GitHub account already anchored elsewhere is refused (no takeover)
//   AP3-10  negative tests for token/refresh + a SQL-created credential row
//   AP3-18  refresh rotation and reuse detection
//   AP3-19  the 6-digit code has a per-session attempt limit
//   AP3-24  consumed email_verifications rows are cleaned up; lookups indexed
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startServer, pgAvailable } from '../helpers/server.mjs';
import { closeDb, sql, TEST_DB, TEST_PEPPER } from '../helpers/db.mjs';
import { rnd, freshEmail, verifyEmail, newSession, sendCode, confirmCode, createTracker } from '../helpers/identity-flow.mjs';

const skip = !pgAvailable() && 'TEST_PG_HOST not set';
const SERVER_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

let srv;
const track = createTracker();
const extraSessions = new Set();

test.before(async () => {
  if (skip) return;
  srv = await startServer({ env: { SMTP_HOST: '', SMTP_USER: '', SMTP_PASS: '' } });
});
test.after(async () => {
  if (skip) return;
  const ids = [...extraSessions];
  if (ids.length) {
    await sql('DELETE FROM challenges WHERE challenge_id = ANY($1)',
      [ids.flatMap((s) => [s, `email:${s}`, `email-attempts:${s}`])]);
  }
  await track.cleanup();
  await srv.stop();
  await closeDb();
});

/** A tracked session id whose helper rows (incl. the AP3-19 counter) get cleaned. */
function remember(sessionId) { extraSessions.add(sessionId); track.add({ sessionId }); return sessionId; }

async function signedIn(tag) {
  const { sessionId, userId } = await verifyEmail(srv, freshEmail(tag), undefined, track);
  remember(sessionId);
  const r = await srv.api('/hhttps/role/declare', { method: 'POST', body: { sessionId } });
  assert.equal(r.status, 200, r.text);
  return { sessionId, userId, token: r.json.hhttps.token, refreshToken: r.json.hhttps.refreshToken };
}

// ─── AP3-03 (#46) ────────────────────────────────────────────────────────────
test('AP3-03: auth/finish without `response` answers 400 instead of hanging', { skip }, async () => {
  const sessionId = remember(await newSession(srv, {}, track));
  const started = Date.now();
  const r = await srv.api('/hhttps/webauthn/auth/finish', { method: 'POST', body: { sessionId } });
  assert.equal(r.status, 400, r.text);
  assert.match(r.json.error, /response\.id/);
  assert.ok(Date.now() - started < 4000, 'answered promptly (used to time out)');
  // Same for a body that is not an object at all, and for a non-string response.id.
  assert.equal((await srv.api('/hhttps/webauthn/auth/finish', { method: 'POST', body: {} })).status, 400);
  assert.equal((await srv.api('/hhttps/webauthn/auth/finish',
    { method: 'POST', body: { sessionId, response: { id: { a: 1 } } } })).status, 400);
});

test('AP3-03: email/status and github/status refuse a non-string sessionId', { skip }, async () => {
  for (const p of ['/hhttps/email/status', '/hhttps/verify/github/status']) {
    const r = await srv.api(p, { method: 'POST', body: { sessionId: { $ne: null } } });
    assert.equal(r.status, 400, `${p}: ${r.text}`);
  }
});

// ─── AP3-04 (#54) ────────────────────────────────────────────────────────────
test('AP3-04: /email/verify redirects on array/object query parameters', { skip }, async () => {
  const sessionId = remember(await newSession(srv, {}, track));
  for (const qs of [`token=a&token=b&session=${sessionId}`, `token[x]=a&session=${sessionId}`,
                    `token=a&session=${sessionId}&session=${sessionId}`]) {
    const res = await fetch(`${srv.baseUrl}/hhttps/email/verify?${qs}`, { redirect: 'manual' });
    assert.equal(res.status, 302, qs);
    assert.match(res.headers.get('location'), /email_verify=error&reason=missing_params/, qs);
  }
});

// ─── AP3-05 (#61) ────────────────────────────────────────────────────────────
test('AP3-05: the code never outlives the session it belongs to', { skip }, async () => {
  const email = freshEmail('ap3-05');
  const sessionId = remember(await newSession(srv, {}, track));
  const sent = await sendCode(srv, sessionId, email, {}, track);
  assert.match(sent.expiresIn, /^\d+ Minuten$/);

  const [row] = await sql(
    `SELECT v.expires_at AS code_exp, s.expires_at AS sess_exp, c.expires_at AS ctx_exp
       FROM email_verifications v
       JOIN sessions s ON s.session_id = v.session_id
       LEFT JOIN challenges c ON c.challenge_id = 'email:' || v.session_id
      WHERE v.session_id = $1`, [sessionId]);
  assert.ok(row, 'verification row exists');
  // (a second of slack: the server computes the remainder in JS, the row gets NOW() in SQL)
  const slack = 1000;
  assert.ok(new Date(row.code_exp) - new Date(row.sess_exp) <= slack,
    `code TTL ${row.code_exp} must not exceed session TTL ${row.sess_exp}`);
  assert.ok(new Date(row.ctx_exp) - new Date(row.sess_exp) <= slack, 'parked context TTL is aligned too');
});

test('AP3-05: a session with almost no time left is refused instead of mailing a dead code', { skip }, async () => {
  const sessionId = remember(await newSession(srv, {}, track));
  await sql(`UPDATE sessions SET expires_at = NOW() + INTERVAL '20 seconds' WHERE session_id = $1`, [sessionId]);
  const r = await srv.api('/hhttps/email/send', { method: 'POST', body: { sessionId, email: freshEmail('ap3-05b') } });
  assert.equal(r.status, 410, r.text);
  assert.equal(r.json.error, 'session_expired');
});

// ─── AP3-08 (#65) ────────────────────────────────────────────────────────────
test('AP3-08: the identity cookie stops claiming `verified` once the token is revoked', { skip }, async () => {
  const { sessionId, token } = await signedIn('ap3-08');
  const declare = await srv.api('/hhttps/role/declare', { method: 'POST', body: { sessionId } });
  const setCookie = declare.headers.getSetCookie?.().find((c) => c.startsWith('hhttps_identity='))
    || declare.headers.get('set-cookie');
  assert.ok(setCookie, 'role/declare sets the identity cookie');
  const cookie = setCookie.split(';')[0];
  const live = declare.json.hhttps.token;

  const before = await fetch(`${srv.baseUrl}/`, { headers: { cookie } });
  assert.equal(before.headers.get('hhttps-status'), 'verified');

  const rev = await srv.api('/hhttps/revoke', { method: 'POST', body: { token: live } });
  assert.equal(rev.status, 200, rev.text);

  // Same cookie, another browser: the signature still verifies — the revocation
  // list must be what decides.
  const after = await fetch(`${srv.baseUrl}/`, { headers: { cookie } });
  assert.equal(after.headers.get('hhttps-status'), 'issuer');
  assert.equal(after.headers.get('hhttps-role'), null);
  assert.ok(String(after.headers.get('set-cookie') || '').includes('hhttps_identity='), 'the cookie is cleared');
  assert.ok(token);
});

// ─── AP3-18 (#116) ───────────────────────────────────────────────────────────
test('AP3-18: refresh tokens rotate, and a reused one kills the whole family', { skip }, async () => {
  const { refreshToken } = await signedIn('ap3-18');

  const first = await srv.api('/hhttps/token/refresh', { method: 'POST', body: { refreshToken } });
  assert.equal(first.status, 200, first.text);
  assert.ok(first.json.refreshToken, 'a rotated refresh token comes back');
  assert.notEqual(first.json.refreshToken, refreshToken);

  // The rotated-away token is dead …
  const reuse = await srv.api('/hhttps/token/refresh', { method: 'POST', body: { refreshToken } });
  assert.equal(reuse.status, 401, reuse.text);
  assert.equal(reuse.json.error, 'refresh_token_reuse_detected');

  // … and the reuse took the newest token with it (RFC 6819 §5.2.2.3).
  const afterFamilyKill = await srv.api('/hhttps/token/refresh',
    { method: 'POST', body: { refreshToken: first.json.refreshToken } });
  assert.equal(afterFamilyKill.status, 401, afterFamilyKill.text);
});

test('AP3-10: token/refresh negative cases — missing, garbage, access token, revoked', { skip }, async () => {
  const { token, refreshToken } = await signedIn('ap3-10r');
  assert.equal((await srv.api('/hhttps/token/refresh', { method: 'POST', body: {} })).status, 400);
  assert.equal((await srv.api('/hhttps/token/refresh', { method: 'POST', body: { refreshToken: 42 } })).status, 400);
  assert.equal((await srv.api('/hhttps/token/refresh', { method: 'POST', body: { refreshToken: 'not.a.jwt' } })).status, 401);
  // An ACCESS token is not a refresh token.
  assert.equal((await srv.api('/hhttps/token/refresh', { method: 'POST', body: { refreshToken: token } })).status, 401);
  // Revoking the sign-in ends the refresh chain (AP4-03) → 401, not a new token.
  await srv.api('/hhttps/revoke', { method: 'POST', body: { token } });
  const r = await srv.api('/hhttps/token/refresh', { method: 'POST', body: { refreshToken } });
  assert.equal(r.status, 401, r.text);
});

// ─── AP3-19 (#122) ───────────────────────────────────────────────────────────
test('AP3-19: five wrong codes burn the verification for that session', { skip }, async () => {
  const email = freshEmail('ap3-19');
  const sessionId = remember(await newSession(srv, {}, track));
  const sent = await sendCode(srv, sessionId, email, {}, track);
  const wrong = String((Number(sent.devCode) + 1) % 1_000_000).padStart(6, '0');

  for (let i = 1; i <= 4; i++) {
    const r = await confirmCode(srv, sessionId, wrong);
    assert.equal(r.status, 400, `attempt ${i}: ${r.text}`);
    assert.equal(r.json.attemptsLeft, 5 - i);
  }
  const fifth = await confirmCode(srv, sessionId, wrong);
  assert.equal(fifth.status, 429, fifth.text);
  assert.equal(fifth.json.error, 'too_many_attempts');

  // The RIGHT code is worthless now — the row was consumed and the context dropped.
  const real = await confirmCode(srv, sessionId, sent.devCode);
  assert.equal(real.status, 429, real.text);
  const [row] = await sql('SELECT used FROM email_verifications WHERE session_id = $1', [sessionId]);
  assert.equal(row.used, true, 'pending verification burned');
});

test('AP3-19: a correct code is unaffected by earlier wrong guesses', { skip }, async () => {
  const email = freshEmail('ap3-19b');
  const sessionId = remember(await newSession(srv, {}, track));
  const sent = await sendCode(srv, sessionId, email, {}, track);
  const wrong = String((Number(sent.devCode) + 7) % 1_000_000).padStart(6, '0');
  assert.equal((await confirmCode(srv, sessionId, wrong)).status, 400);
  const ok = await confirmCode(srv, sessionId, sent.devCode);
  assert.equal(ok.status, 200, ok.text);
  track.add({ email, userId: ok.json.userId });
  const left = await sql(`SELECT 1 FROM challenges WHERE challenge_id = $1`, [`email-attempts:${sessionId}`]);
  assert.equal(left.length, 0, 'the counter row is removed on success');
});

// ─── AP3-10 (#83): a credential row created by SQL ───────────────────────────
test('AP3-10: auth/start offers a SQL-created credential and finish refuses a forged response', { skip }, async () => {
  const { sessionId, userId } = await verifyEmail(srv, freshEmail('ap3-10c'), undefined, track);
  remember(sessionId);
  const credId = crypto.randomBytes(16).toString('base64url');
  await sql(
    `INSERT INTO credentials (credential_id, user_id, public_key, counter, transports, device_type, backed_up)
     VALUES ($1, $2, $3, 0, $4, 'singleDevice', FALSE)`,
    [credId, userId, Buffer.from('not-a-real-key'), ['internal']]
  );

  const start = await srv.api('/hhttps/webauthn/auth/start', { method: 'POST', body: { userId } });
  assert.equal(start.status, 200, start.text);
  const offered = start.json.options.allowCredentials.map((c) => (typeof c.id === 'string' ? c.id : ''));
  assert.ok(JSON.stringify(start.json.options).includes(credId) || offered.includes(credId),
    'the stored credential is offered');

  const finish = await srv.api('/hhttps/webauthn/auth/finish', {
    method: 'POST',
    body: { sessionId: start.json.sessionId, response: { id: credId, rawId: credId, type: 'public-key', response: {} } },
  });
  assert.ok(finish.status >= 400 && finish.status < 500, `forged response refused: ${finish.status}`);
  assert.ok(finish.json, 'a JSON error, not a hang or an HTML 500 page');
});

// ─── AP3-24 (#128) ───────────────────────────────────────────────────────────
test('AP3-24: the phase-10 boot DDL indexes the lookups and cleans consumed rows', { skip }, async () => {
  const file = path.join(SERVER_DIR, 'sql', 'migration-phase-10-review-welle-2.sql');
  const ddl = fs.readFileSync(file, 'utf8').split('-- >>> BOOT-DDL END')[0];
  assert.ok(ddl.includes('CREATE INDEX IF NOT EXISTS email_verifications_session_idx'));
  await sql(ddl);            // idempotent — applied twice on purpose
  await sql(ddl);

  const idx = await sql(
    `SELECT indexname FROM pg_indexes WHERE tablename = 'email_verifications' AND indexname = ANY($1)`,
    [['email_verifications_session_idx', 'email_verifications_code_session_idx']]
  );
  assert.equal(idx.length, 2, 'both indexes exist');

  // The consumed-row leak: an expired row with used = TRUE used to survive forever.
  const sessionId = `ap3-24-${rnd()}`;
  await sql(
    `INSERT INTO email_verifications (token, code, email, domain, level, trust_bonus, category, session_id, used, expires_at)
     VALUES ($1, $2, $3, 'example.org', 'email-verified', 0, 'generic', $4, TRUE, NOW() - INTERVAL '1 day')`,
    [crypto.randomBytes(16).toString('hex'), crypto.randomBytes(16).toString('hex'),
     crypto.randomBytes(16).toString('hex'), sessionId]
  );
  await sql('SELECT cleanup_expired()');
  const left = await sql('SELECT 1 FROM email_verifications WHERE session_id = $1', [sessionId]);
  assert.equal(left.length, 0, 'expired + used rows are deleted now');
});

// ─── AP3-09 (#76) / AP4-11: GitHub anchor collision ─────────────────────────
// In-process against external-verify.js: GitHub itself is stubbed out via fetch.
test('AP3-09: a GitHub account anchored to another user cannot be taken over', { skip }, async (t) => {
  process.env.DB_HOST = TEST_DB.host; process.env.DB_USER = TEST_DB.user;
  process.env.DB_NAME = TEST_DB.database; process.env.DB_PASSWORD = TEST_DB.password;
  process.env.GITHUB_CLIENT_ID = 'test-id';
  process.env.GITHUB_CLIENT_SECRET = 'test-secret';
  process.env.HHTTPS_VERIFICATION_PEPPER = TEST_PEPPER;
  const db = await import('../../db.js');
  const { handleGithubCallback } = await import('../../external-verify.js');

  const githubId = 987_654_321;
  const hash = crypto.createHash('sha256').update(`github:${githubId}:${TEST_PEPPER}`).digest('hex');
  const owner = `ap3-09-owner-${rnd()}`;
  const attackerUser = `ap3-09-attacker-${rnd()}`;
  const sessionId = `ap3-09-sess-${rnd()}`;
  const state = `ap3-09-state-${rnd()}`;

  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url).includes('access_token')) return { ok: true, json: async () => ({ access_token: 'gho_x' }) };
    return { ok: true, json: async () => ({ id: githubId, created_at: '2015-01-01T00:00:00Z', public_repos: 20, followers: 5 }) };
  };
  t.after(async () => {
    globalThis.fetch = realFetch;
    await sql('DELETE FROM external_verification_anchors WHERE anchor_hash = $1', [hash]);
    await sql('DELETE FROM github_oauth_pending WHERE state = $1', [state]);
    await sql('DELETE FROM sessions WHERE session_id = $1', [sessionId]);
    await db.close();
  });

  // The GitHub account already belongs to `owner`.
  await sql(
    `INSERT INTO external_verification_anchors (provider, anchor_hash, user_id, trust_score_assigned)
     VALUES ('github', $1, $2, 70)`, [hash, owner]);
  // A second identity runs the OAuth flow with the same GitHub account.
  await db.sessions.create(sessionId, { userId: attackerUser, credentialId: null,
    deviceType: 'pending', backedUp: false, verified: true, trustScore: 0 }, 600_000);
  await sql('INSERT INTO github_oauth_pending (state, session_id) VALUES ($1, $2)', [state, sessionId]);

  await assert.rejects(
    () => handleGithubCallback({ code: 'c', state, redirectBase: 'http://localhost' }),
    (e) => e.code === 'github_already_bound');

  const [anchor] = await sql('SELECT user_id FROM external_verification_anchors WHERE anchor_hash = $1', [hash]);
  assert.equal(anchor.user_id, owner, 'the anchor still belongs to the first user');
  const session = await db.sessions.get(sessionId);
  assert.ok(!session.githubVerified, 'the second session was NOT marked github-verified');
});
