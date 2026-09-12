// W-6 / W-24: shared helpers for the email-first identity flow in the
// integration tests (session → /email/send → /email/confirm-code) plus a
// cleanup that removes EVERY row a flow leaves behind.
//
//   const track = createTracker();
//   const { sessionId, userId, pseudonym } = await verifyEmail(srv, freshEmail('t4'), 'Anna', track);
//   … test.after(() => track.cleanup());
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { sql, TEST_PEPPER } from './db.mjs';
import { emailAnchorHash } from '../../identity.js';

export const rnd = () => crypto.randomBytes(5).toString('hex');

/** Unique test address; `tag` names the calling suite/case in the local part. */
export const freshEmail = (tag = 't') => `${tag}-${rnd()}@example.org`;

export function decodeJwtPayload(token) {
  const [, payload] = String(token).split('.');
  return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
}

/** Rows to remove after a flow. `add()` accepts any subset of the three keys. */
export function createTracker() {
  const t = { emails: new Set(), userIds: new Set(), sessionIds: new Set() };
  t.add = ({ email, userId, sessionId } = {}) => {
    if (email) t.emails.add(email);
    if (userId) t.userIds.add(userId);
    if (sessionId) t.sessionIds.add(sessionId);
    return t;
  };
  t.cleanup = () => cleanupIdentity({
    emails: [...t.emails], userIds: [...t.userIds], sessionIds: [...t.sessionIds],
  });
  return t;
}

/** POST /hhttps/session/start → sessionId (tracked when a tracker is given). */
export async function newSession(srv, body = {}, tracker = null) {
  const r = await srv.api('/hhttps/session/start', { method: 'POST', body });
  assert.equal(r.status, 200, r.text);
  tracker?.add({ sessionId: r.json.sessionId });
  return r.json.sessionId;
}

/** POST /hhttps/email/send in dev mode → { devCode, devToken, … } (asserts 200). */
export async function sendCode(srv, sessionId, email, extra = {}, tracker = null) {
  const r = await srv.api('/hhttps/email/send', { method: 'POST', body: { sessionId, email, ...extra } });
  assert.equal(r.status, 200, r.text);
  assert.equal(r.json.devMode, true, 'dev mode expected (no SMTP)');
  tracker?.add({ email, sessionId });
  return r.json;
}

/** POST /hhttps/email/confirm-code → raw { status, json, text } (no assertion). */
export function confirmCode(srv, sessionId, code) {
  return srv.api('/hhttps/email/confirm-code', { method: 'POST', body: { sessionId, code } });
}

/**
 * Full happy path: new session → send → confirm. Returns the email-verified
 * session: { sessionId, userId, pseudonym, methods, anchorCreated }.
 */
export async function verifyEmail(srv, email, pseudonym = undefined, tracker = null) {
  const sessionId = await newSession(srv, {}, tracker);
  const sent = await sendCode(srv, sessionId, email, pseudonym ? { pseudonym } : {}, tracker);
  const c = await confirmCode(srv, sessionId, sent.devCode);
  assert.equal(c.status, 200, c.text);
  tracker?.add({ email, userId: c.json.userId, sessionId });
  return {
    sessionId, userId: c.json.userId, pseudonym: c.json.pseudonym,
    methods: c.json.methods, anchorCreated: c.json.anchorCreated,
  };
}

/**
 * Removes everything a flow may have written: identity_anchors (by the
 * server's pepper), identity_claims_cache, sessions (by id AND by anchor
 * userId), email_verifications, the challenge rows (`email:<sid>`, `<sid>`,
 * WebAuthn `<userId>`), refresh_tokens and tokens.
 */
export async function cleanupIdentity({ emails = [], userIds = [], sessionIds = [] } = {}) {
  const hashes = [...new Set(emails.map((e) => emailAnchorHash(e, TEST_PEPPER)))];
  if (sessionIds.length) {
    await sql('DELETE FROM challenges WHERE challenge_id = ANY($1)',
      [[...sessionIds, ...sessionIds.map((s) => `email:${s}`)]]);
    await sql('DELETE FROM email_verifications WHERE session_id = ANY($1)', [sessionIds]);
  }
  if (userIds.length) {
    // WebAuthn register/auth challenges are keyed by the (stable) userId.
    await sql('DELETE FROM challenges WHERE challenge_id = ANY($1) OR user_id = ANY($1)', [userIds]);
    await sql('DELETE FROM refresh_tokens WHERE user_id = ANY($1)', [userIds]);
    await sql('DELETE FROM tokens WHERE user_id = ANY($1)', [userIds]);
    await sql('DELETE FROM identity_claims_cache WHERE user_id = ANY($1)', [userIds]);
  }
  if (sessionIds.length || userIds.length) {
    await sql('DELETE FROM sessions WHERE session_id = ANY($1) OR user_id = ANY($2)', [sessionIds, userIds]);
  }
  if (hashes.length) await sql('DELETE FROM identity_anchors WHERE email_hash = ANY($1)', [hashes]);
}
