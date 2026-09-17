// Review 2026-09, Welle 3 — AP3 integration tests (identity / session / e-mail
// / GitHub). Welle 3 is a refactoring wave, so these pin the behaviour the
// merges must not move:
//
//   AP3-30 (#141)  the duplicate /session/email/start is gone; /session/start
//                  answers exactly as before and /hhttps/info no longer lists it
//   AP3-33 (#148)  code path and magic-link path share ONE confirmation core:
//                  same ordering (#22), same error vocabulary
//   AP3-34 (#156)  /token/refresh keeps the refresh semantics it had while
//                  sharing the "is this jti active" check with checkTokenValid
//   AP3-41 (#183)  the GitHub return page had no test at all
import test from 'node:test';
import assert from 'node:assert/strict';
import { startServer, pgAvailable } from '../helpers/server.mjs';
import { closeDb, sql } from '../helpers/db.mjs';
import { freshEmail, newSession, sendCode, confirmCode, verifyEmail, createTracker }
  from '../helpers/identity-flow.mjs';

const skip = !pgAvailable() && 'TEST_PG_HOST not set';

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

function remember(sessionId) { extraSessions.add(sessionId); track.add({ sessionId }); return sessionId; }

/** GET without following redirects → { status, location, text }. */
async function raw(path) {
  const res = await fetch(srv.baseUrl + path, { redirect: 'manual' });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* html or plain text */ }
  return { status: res.status, location: res.headers.get('location'), text, json };
}

// ─── AP3-30 (#141) ───────────────────────────────────────────────────────────
test('AP3-30: the duplicate /hhttps/session/email/start is gone', { skip }, async () => {
  const r = await srv.api('/hhttps/session/email/start', { method: 'POST', body: {} });
  assert.equal(r.status, 404, 'the twin route no longer exists');

  const info = await srv.api('/hhttps/info');
  assert.equal(info.status, 200);
  const paths = Object.keys(info.json.endpoints || {}).join(' ');
  assert.ok(!paths.includes('session/email/start'), '/hhttps/info must not advertise it any more');
  assert.ok(paths.includes('POST /hhttps/session/start'), 'the surviving bootstrap is still listed');
});

test('AP3-30: /session/start is unchanged — trust 0, no verified method, pseudonym kept', { skip }, async () => {
  const r = await srv.api('/hhttps/session/start', { method: 'POST', body: { pseudonym: 'Anna B.' } });
  assert.equal(r.status, 200, r.text);
  remember(r.json.sessionId);
  assert.equal(r.json.trustScore, 0);
  assert.equal(r.json.method, 'session-pending');
  assert.equal(r.json.pseudonym, 'Anna B.');
  assert.ok(r.json.userId);

  // A bootstrap session carries no confirmed method, so it cannot mint a token.
  const declare = await srv.api('/hhttps/role/declare', { method: 'POST', body: { sessionId: r.json.sessionId } });
  assert.equal(declare.status, 403);
  assert.equal(declare.json.error, 'email_verification_required');
});

// ─── AP3-33 (#148) ───────────────────────────────────────────────────────────
test('AP3-33: the magic link loads the session BEFORE consuming the token (#22)', { skip }, async () => {
  const email = freshEmail('w3-link');
  const sessionId = remember(await newSession(srv, {}, track));
  const sent = await sendCode(srv, sessionId, email, {}, track);

  // Redeem the magic link against an UNKNOWN session: the answer is the same
  // as before, but the token must survive — it belongs to the real session.
  const wrong = await raw(
    `/hhttps/email/verify?token=${sent.devToken}&session=00000000-0000-4000-8000-000000000000`);
  assert.equal(wrong.status, 302);
  assert.match(wrong.location, /email_verify=error&reason=session_expired/);

  // The token was NOT burned: the legitimate session can still use it.
  const ok = await raw(`/hhttps/email/verify?token=${sent.devToken}&session=${sessionId}`);
  assert.equal(ok.status, 302);
  const loc = ok.location;
  assert.match(loc, /email_verify=success/, loc);
  assert.match(loc, /pseudonym=/);

  const status = await srv.api('/hhttps/email/status', { method: 'POST', body: { sessionId } });
  assert.equal(status.json.emailVerified, true);
  track.add({ email, sessionId });
});

test('AP3-33: both paths report the SAME reason when the parked context is gone', { skip }, async () => {
  // Code path.
  const e1 = freshEmail('w3-ctx-code');
  const s1 = remember(await newSession(srv, {}, track));
  const sent1 = await sendCode(srv, s1, e1, {}, track);
  await sql('DELETE FROM challenges WHERE challenge_id = $1', [`email:${s1}`]);
  const c1 = await confirmCode(srv, s1, sent1.devCode);
  assert.equal(c1.status, 409);
  assert.equal(c1.json.error, 'email_context_missing');

  // Magic-link path — same vocabulary, rendered as a redirect reason.
  const e2 = freshEmail('w3-ctx-link');
  const s2 = remember(await newSession(srv, {}, track));
  const sent2 = await sendCode(srv, s2, e2, {}, track);
  await sql('DELETE FROM challenges WHERE challenge_id = $1', [`email:${s2}`]);
  const r2 = await raw(`/hhttps/email/verify?token=${sent2.devToken}&session=${s2}`);
  assert.equal(r2.status, 302);
  assert.match(r2.location, /reason=email_context_missing/);
});

test('AP3-33: a token issued for another session is still refused', { skip }, async () => {
  const eA = freshEmail('w3-mismatch-a');
  const sA = remember(await newSession(srv, {}, track));
  const sentA = await sendCode(srv, sA, eA, {}, track);
  const sB = remember(await newSession(srv, {}, track));

  const r = await raw(`/hhttps/email/verify?token=${sentA.devToken}&session=${sB}`);
  assert.equal(r.status, 302);
  assert.match(r.location, /reason=session_mismatch/);
});

// ─── AP3-34 (#156) ───────────────────────────────────────────────────────────
test('AP3-34: /token/refresh still rejects a non-refresh JWT and an unknown jti', { skip }, async () => {
  const email = freshEmail('w3-refresh');
  const { sessionId, userId } = await verifyEmail(srv, email, 'Rita', track);
  remember(sessionId);
  const d = await srv.api('/hhttps/role/declare', { method: 'POST', body: { sessionId } });
  assert.equal(d.status, 200, d.text);
  const { token, refreshToken } = d.json.hhttps;

  // An ACCESS token is not a refresh token (the sub check runs before any DB read).
  const asAccess = await srv.api('/hhttps/token/refresh', { method: 'POST', body: { refreshToken: token } });
  assert.equal(asAccess.status, 401);
  assert.equal(asAccess.json.error, 'Kein Refresh-Token');

  // A structurally valid refresh token whose row is gone → the shared wording.
  await sql('DELETE FROM refresh_tokens WHERE user_id = $1', [userId]);
  const gone = await srv.api('/hhttps/token/refresh', { method: 'POST', body: { refreshToken } });
  assert.equal(gone.status, 401);
  assert.equal(gone.json.error, 'Refresh-Token nicht aktiv',
    'same message checkTokenValid produces — one definition, one wording');
});

test('AP3-34/AP3-43: a refreshed token carries the full surface from the token itself', { skip }, async () => {
  const email = freshEmail('w3-surface');
  const { sessionId } = await verifyEmail(srv, email, 'Surf', track);
  remember(sessionId);
  const d = await srv.api('/hhttps/role/declare', { method: 'POST', body: { sessionId } });
  assert.equal(d.status, 200, d.text);

  const r = await srv.api('/hhttps/token/refresh',
    { method: 'POST', body: { refreshToken: d.json.hhttps.refreshToken } });
  assert.equal(r.status, 200, r.text);

  const payload = JSON.parse(Buffer.from(r.json.token.split('.')[1], 'base64url').toString('utf8'));
  assert.ok(payload.verified_methods.includes('email'), 'the confirmed method survives the refresh');
  assert.equal(payload.email_verified, true);
  assert.equal(payload.passkey_verified, false);
  assert.equal(payload.verification_status, 'verified');
  assert.equal(payload.pseudonym, 'Surf');
  assert.ok(r.json.refreshToken && r.json.refreshToken !== d.json.hhttps.refreshToken, 'still rotates');
});

// ─── AP3-41 (#183): the GitHub return page ───────────────────────────────────
test('AP3-41: the GitHub callback renders a self-closing return page, not a redirect', { skip }, async () => {
  // Without a configured OAuth app handleGithubCallback throws; the route must
  // still answer with the HTML page (200) rather than a redirect or a 500.
  const r = await raw('/hhttps/verify/github/callback?code=abc&state=nope');
  assert.equal(r.status, 200, r.text);
  assert.match(r.text, /<!DOCTYPE html>/i);
  assert.match(r.text, /GitHub verification failed/);
  assert.match(r.text, /window\.close\(\)/, 'the popup closes itself');
  assert.match(r.text, /Du kannst diesen Tab schließen/, 'bilingual');
});

test('AP3-41: the GitHub callback maps provider errors and missing params to the SPA', { skip }, async () => {
  const denied = await raw('/hhttps/verify/github/callback?error=access_denied');
  assert.equal(denied.status, 302);
  assert.match(denied.location, /github_verify=error&reason=access_denied/);

  const bare = await raw('/hhttps/verify/github/callback');
  assert.equal(bare.status, 302);
  assert.match(bare.location, /reason=missing_params/);
});

test('AP3-41: /verify/github/start gates on the session before anything else', { skip }, async () => {
  const none = await raw('/hhttps/verify/github/start');
  assert.equal(none.status, 400);

  const unknown = await raw('/hhttps/verify/github/start?session=00000000-0000-4000-8000-000000000000');
  assert.equal(unknown.status, 401);

  // A session without a confirmed e-mail is refused by the AK-11 gate — BEFORE
  // the "is GitHub configured" check, so the answer does not leak the config.
  const sessionId = remember(await newSession(srv, {}, track));
  const pending = await raw(`/hhttps/verify/github/start?session=${sessionId}`);
  assert.equal(pending.status, 403);
  assert.equal(pending.json.error, 'email_verification_required');
});

// ─── AP3-37 (#177): one error shape across the block ─────────────────────────
test('AP3-37: every JSON failure in the identity block is { error: <code> }', { skip }, async () => {
  const cases = [
    ['/hhttps/webauthn/register/start',  {},                     400],
    ['/hhttps/webauthn/register/finish', {},                     400],
    ['/hhttps/webauthn/auth/finish',     {},                     400],
    ['/hhttps/token/refresh',            {},                     400],
    ['/hhttps/email/send',               { email: 'nope' },      400],
    ['/hhttps/email/confirm-code',       { sessionId: 'x' },     400],
    ['/hhttps/email/status',             {},                     400],
    ['/hhttps/verify/github/status',     {},                     400],
  ];
  for (const [path, body, status] of cases) {
    const r = await srv.api(path, { method: 'POST', body });
    assert.equal(r.status, status, `${path} → ${r.status} ${r.text}`);
    assert.equal(typeof r.json?.error, 'string', `${path} answers { error: <string> }`);
  }
});

// ─── AP3-07 (#199): a malformed identity cookie must not 500 every route ─────
test('AP3-07: an undecodable hhttps identity cookie is ignored, not fatal', { skip }, async () => {
  const bad = await srv.api('/hhttps/info', { headers: { cookie: 'hhttps_identity=%zz%' } });
  assert.equal(bad.status, 200, 'the request is served as if no cookie were sent');
  assert.ok(bad.json?.endpoints, bad.text);

  // The same holds for a route that reads the cookie's identity.
  const page = await raw('/');
  assert.ok(page.status === 200 || page.status === 304, `landing page still serves (${page.status})`);
});
