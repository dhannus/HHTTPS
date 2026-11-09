// AK-33 … AK-35 (pseudonym-once): the account display name is asked once and
// lives in identity_anchors. /hhttps/oauth/approve changes it only with an
// explicit `set_pseudonym: true`; afterwards every platform gets the new name,
// even while the user's signed HHTTPS token still carries the old one.
// Runs server.js as a child process (HTTP) and asserts via SQL.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { startServer, pgAvailable } from '../helpers/server.mjs';
import { sql, closeDb } from '../helpers/db.mjs';
import { rnd, freshEmail as mkEmail, verifyEmail, decodeJwtPayload, createTracker } from '../helpers/identity-flow.mjs';

const skip = !pgAvailable() && 'TEST_PG_HOST not set';
const REDIRECT_URI = 'http://localhost/cb';
const freshEmail = () => mkEmail('t10');

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

// ─── helpers ────────────────────────────────────────────────────────────────

async function createClient() {
  const clientId = `test-t10-${rnd()}`;
  await sql(
    `INSERT INTO oauth_clients
       (client_id, client_secret_hash, name, homepage_url, redirect_uris, allowed_scopes,
        subject_type, verified, is_active, verification_status)
     VALUES ($1, NULL, $2, $3, $4, $5, 'pairwise', TRUE, TRUE, 'verified')`,
    [clientId, `T10 test client ${clientId}`, 'http://localhost', JSON.stringify([REDIRECT_URI]), JSON.stringify(['openid', 'role'])]
  );
  clientIds.add(clientId);
  return clientId;
}

/** Email flow + role/declare → { token, userId, pseudonym }. */
async function hhttpsToken(email, pseudonym) {
  const v = await verifyEmail(srv, email, pseudonym, track);
  const d = await srv.api('/hhttps/role/declare', { method: 'POST', body: { sessionId: v.sessionId } });
  assert.equal(d.status, 200, d.text);
  return { token: d.json.hhttps.token, userId: v.userId, pseudonym: v.pseudonym };
}

/** approve (with optional extra body) → token exchange → { approve, id }. */
async function codeFlow(token, clientId, extra = {}) {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const a = await srv.api('/hhttps/oauth/approve', {
    method: 'POST',
    body: { token, client_id: clientId, redirect_uri: REDIRECT_URI, scope: 'openid',
            code_challenge: challenge, code_challenge_method: 'S256', ...extra }
  });
  assert.equal(a.status, 200, a.text);
  const code = new URL(a.json.redirect).searchParams.get('code');
  const t = await srv.api('/hhttps/oauth/token', {
    method: 'POST',
    body: { grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI,
            client_id: clientId, code_verifier: verifier }
  });
  assert.equal(t.status, 200, t.text);
  return { approve: a.json, id: decodeJwtPayload(t.json.id_token) };
}

async function anchorName(userId) {
  const rows = await sql('SELECT pseudonym FROM identity_anchors WHERE user_id = $1', [userId]);
  return rows[0]?.pseudonym;
}

// ─── tests ──────────────────────────────────────────────────────────────────

test('AK-34: a bare `pseudonym` on approve does NOT change an existing account name', { skip }, async () => {
  const clientId = await createClient();
  const { token, userId } = await hhttpsToken(freshEmail(), 'Anna');
  const { approve, id } = await codeFlow(token, clientId, { pseudonym: 'Mallory' });
  assert.equal(id.preferred_username, 'Anna', 'account name wins over consent input');
  assert.equal(approve.pseudonym, 'Anna', 'AK-35: approve echoes the account name');
  assert.equal(await anchorName(userId), 'Anna', 'anchor unchanged');
});

test('AK-34: set_pseudonym changes the account name; later approves use it although the token still says the old one', { skip }, async () => {
  const clientA = await createClient();
  const clientB = await createClient();
  const { token, userId } = await hhttpsToken(freshEmail(), 'Anna');

  const first = await codeFlow(token, clientA, { pseudonym: 'Waldfee42', set_pseudonym: true });
  assert.equal(first.id.preferred_username, 'Waldfee42', 'new name in the ID token');
  assert.equal(first.approve.pseudonym, 'Waldfee42', 'AK-35: approve echoes the new name');
  assert.equal(await anchorName(userId), 'Waldfee42', 'anchor updated');
  const cache = await sql('SELECT pseudonym FROM identity_claims_cache WHERE user_id = $1', [userId]);
  if (cache[0]) assert.equal(cache[0].pseudonym, 'Waldfee42', 'claims cache follows the anchor');

  // Same (old) HHTTPS token, another platform, no name sent → anchor wins.
  assert.equal(decodeJwtPayload(token).pseudonym, 'Anna', 'precondition: token still carries the old name');
  const second = await codeFlow(token, clientB);
  assert.equal(second.id.preferred_username, 'Waldfee42', 'the changed name reaches every platform');
});

test('AK-33/AK-34: a generated name is replaced on the first consent', { skip }, async () => {
  const clientId = await createClient();
  const { token, userId, pseudonym } = await hhttpsToken(freshEmail());
  assert.match(pseudonym, /^iamhmn_[a-z0-9]{10}$/, 'precondition: server generated the name');
  const { id } = await codeFlow(token, clientId, { pseudonym: 'Fuchs', set_pseudonym: true });
  assert.equal(id.preferred_username, 'Fuchs');
  assert.equal(await anchorName(userId), 'Fuchs');
});

test('AK-34: set_pseudonym with a value that sanitizes to nothing, or a non-boolean flag, changes nothing', { skip }, async () => {
  const clientId = await createClient();
  const { token, userId } = await hhttpsToken(freshEmail(), 'Anna');
  const a = await codeFlow(token, clientId, { pseudonym: '<>!?', set_pseudonym: true });
  assert.equal(a.id.preferred_username, 'Anna');
  const b = await codeFlow(token, clientId, { pseudonym: 'Eve', set_pseudonym: 'true' });
  assert.equal(b.id.preferred_username, 'Anna', 'only the JSON boolean true counts');
  assert.equal(await anchorName(userId), 'Anna');
});

test('AK-34: set_pseudonym sanitizes like everywhere else (AK-6)', { skip }, async () => {
  const clientId = await createClient();
  const { token, userId } = await hhttpsToken(freshEmail(), 'Anna');
  const { id } = await codeFlow(token, clientId, { pseudonym: 'Wald<fee>"42' + 'x'.repeat(40), set_pseudonym: true });
  assert.equal(id.preferred_username.length <= 32, true, 'max 32 chars');
  assert.doesNotMatch(id.preferred_username, /[<>"]/, 'forbidden chars stripped');
  assert.equal(await anchorName(userId), id.preferred_username);
});
