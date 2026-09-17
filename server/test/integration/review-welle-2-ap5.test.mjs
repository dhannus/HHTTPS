// Review 2026-09, Welle 2 — AP5 integration tests against a booted server.js.
// The developer portal, the admin queue, /whoami, the webhooks CRUD, PoP and
// the WP-plugin registration had NO tests at all (AP5-10); every case below
// also pins one behavioural fix:
//
//   AP5-05  a revoked machine token no longer passes /hhttps/pop/challenge
//   AP5-06  Delete is offered for exactly the state the server accepts
//   AP5-07  PATCH can clear description / logo_url (null ≠ "unchanged")
//   AP5-08  reject/suspend enforce the state machine server-side (409)
//   AP5-09  a bad ?days= no longer reaches Postgres as 'NaN days'
//   AP5-11  a non-EC-P-256 publicKeyJwk is rejected instead of dropped
//   AP5-20  PATCH is blocked during review; a verified platform falls back
//   AP5-21  a machine token cannot act as a user (whoami/webhooks/portal)
//   AP5-23  logo_url / impressum_url are validated server-side
//   AP5-29  unconfirmed plugin drafts per site apex are capped
//   AP5-30  /hhttps/stats is cached and marked cacheable
//   AP5-31  a DNS check has a minimum interval per client
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { startServer, pgAvailable } from '../helpers/server.mjs';
import { closeDb, sql } from '../helpers/db.mjs';
import { rnd, freshEmail, verifyEmail, createTracker } from '../helpers/identity-flow.mjs';

const skip = !pgAvailable() && 'TEST_PG_HOST not set';

let srv;
const track = createTracker();
const clientIds = new Set();
const operatorIds = new Set();
const adminIds = new Set();

test.before(async () => {
  if (skip) return;
  srv = await startServer({ env: { SMTP_HOST: '', SMTP_USER: '', SMTP_PASS: '' } });
});

test.after(async () => {
  if (skip) return;
  const ids = [...clientIds];
  if (ids.length) {
    await sql('DELETE FROM admin_actions WHERE target_id = ANY($1)', [ids]).catch(() => {});
    await sql('DELETE FROM oauth_clients WHERE client_id = ANY($1)', [ids]);
  }
  if (operatorIds.size) {
    await sql('DELETE FROM machine_operators WHERE operator_id = ANY($1)', [[...operatorIds]]);
  }
  if (adminIds.size) await sql('DELETE FROM admins WHERE user_id = ANY($1)', [[...adminIds]]);
  await track.cleanup();
  await srv.stop();
  await closeDb();
});

const auth = (token) => ({ headers: { authorization: `Bearer ${token}` } });

// The server runs behind `trust proxy 1` and every limiter keys on req.ip.
// Each test announces its own client IP so one case cannot exhaust another's
// budget — the limiters themselves are covered by AP5-17 / AP5-31.
let clientIp = '10.90.0.1';
const api = (p, opts = {}) =>
  srv.api(p, { ...opts, headers: { 'x-forwarded-for': clientIp, ...(opts.headers || {}) } });
const fromIp = (last) => { clientIp = `10.90.0.${last}`; };
// The identity helpers only ever call `srv.api` — hand them the IP-tagged one
// so session/start + email/send + confirm-code share the test's own budget.
const ipSrv = { api: (p, opts) => api(p, opts) };

/** e-mail-verified sign-in that also holds admin rights — `requirePortalUser`
 *  lets admins through, so one identity covers portal AND admin routes
 *  without a WebAuthn ceremony in the harness. */
async function portalAdmin(tag) {
  const { sessionId, userId } = await verifyEmail(ipSrv, freshEmail(tag), undefined, track);
  await sql(`INSERT INTO admins (user_id, note) VALUES ($1, 'welle-2 ap5 test')
             ON CONFLICT (user_id) DO NOTHING`, [userId]);
  adminIds.add(userId);
  const r = await api('/hhttps/role/declare', { method: 'POST', body: { sessionId } });
  assert.equal(r.status, 200, r.text);
  return { userId, sessionId, token: r.json.hhttps.token };
}

/** A client row owned by `ownerUserId` in a given verification state. */
async function seedClient(ownerUserId, overrides = {}) {
  const clientId = `w2ap5-${rnd()}`;
  const row = {
    name: 'W2 AP5 Platform', homepage_url: 'https://example.org',
    redirect_uris: JSON.stringify(['https://example.org/cb']),
    allowed_scopes: JSON.stringify(['openid']),
    contact_email: `ops@example.org`, impressum_url: 'https://example.org/impressum',
    description: 'seeded', logo_url: 'https://example.org/logo.png',
    verification_status: 'unverified', dns_token: `hhttps-verify=${rnd()}`,
    email_verified_at: new Date(), ...overrides,
  };
  await sql(
    `INSERT INTO oauth_clients
       (client_id, name, description, homepage_url, redirect_uris, allowed_scopes,
        subject_type, contact_email, impressum_url, logo_url, owner_user_id,
        verification_status, dns_token, email_verified_at, email_token,
        email_token_expires_at, verified, is_active)
     VALUES ($1,$2,$3,$4,$5,$6,'pairwise',$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,TRUE)`,
    [clientId, row.name, row.description, row.homepage_url, row.redirect_uris,
     row.allowed_scopes, row.contact_email, row.impressum_url, row.logo_url,
     ownerUserId, row.verification_status, row.dns_token, row.email_verified_at,
     row.email_token ?? null, row.email_token_expires_at ?? null,
     row.verification_status === 'verified']
  );
  clientIds.add(clientId);
  return clientId;
}

const statusOf = async (clientId) =>
  (await sql('SELECT verification_status FROM oauth_clients WHERE client_id = $1', [clientId]))[0]
    ?.verification_status;

/** An EC P-256 public JWK plus the machine token bound to it. */
async function machineToken({ withKey = false } = {}) {
  const email = freshEmail('w2ap5-mach');
  const { sessionId } = await verifyEmail(ipSrv, email, undefined, track);
  const jwk = withKey
    ? (({ kty, crv, x, y }) => ({ kty, crv, x, y }))(
        crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' }))
    : undefined;
  const reg = await api('/hhttps/machine/register', { method: 'POST', body: {
    operatorName: 'W2 AP5 Bot', purpose: 'welle-2 ap5 test', contactEmail: email, sessionId,
    ...(jwk ? { publicKeyJwk: jwk } : {}) } });
  assert.equal(reg.status, 201, reg.text);
  operatorIds.add(reg.json.operatorId);
  const t = await api('/hhttps/machine/token', { method: 'POST',
    body: { operatorId: reg.json.operatorId, apiKey: reg.json.apiKey } });
  assert.equal(t.status, 200, t.text);
  return { reg: reg.json, token: t.json.token, jwk };
}

// ───────────────────────────────────────────────────────────────────────────

test('AP5-11: /machine/register rejects a publicKeyJwk that is not an EC P-256 key and echoes keyJkt for a valid one',
  { skip }, async () => {
  fromIp(11);
  const email = freshEmail('w2ap5-jwk');
  const { sessionId } = await verifyEmail(ipSrv, email, undefined, track);
  const body = { operatorName: 'W2 AP5 Bot', purpose: 'welle-2 ap5 test',
    contactEmail: email, sessionId };

  for (const bad of [{ kty: 'RSA', n: 'abc', e: 'AQAB' },
                     { kty: 'EC', crv: 'P-384', x: 'a', y: 'b' },
                     'not-an-object']) {
    const r = await api('/hhttps/machine/register', { method: 'POST',
      body: { ...body, publicKeyJwk: bad } });
    assert.equal(r.status, 400, r.text);
    assert.equal(r.json.error, 'invalid_public_key_jwk');
  }
  // nothing was written for the rejected attempts
  const rows = await sql('SELECT 1 FROM machine_operators WHERE contact_email = $1', [email]);
  assert.equal(rows.length, 0);

  const { reg } = await machineToken({ withKey: true });
  assert.match(reg.keyJkt, /^[A-Za-z0-9_-]{43}$/, 'the thumbprint is returned to the operator');
});

test('AP5-21: a machine token is never a user — whoami, webhooks and the portal reject it with 403',
  { skip }, async () => {
  fromIp(12);
  const { token } = await machineToken();
  const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
  assert.equal(payload.sub, 'machine', 'precondition: this really is a machine token');

  for (const call of [
    () => api('/hhttps/whoami', auth(token)),
    () => api('/hhttps/webhooks', auth(token)),
    () => api('/hhttps/webhooks', { method: 'POST', ...auth(token),
      body: { url: 'https://example.org/hook' } }),
    () => api('/hhttps/developers/clients', auth(token)),
    () => api('/hhttps/admin/clients/pending', auth(token)),
  ]) {
    const r = await call();
    assert.equal(r.status, 403, r.text);
    assert.equal(r.json.error, 'machine_token_not_allowed', r.text);
    assert.ok(!r.text.includes('grant_admin_command'), 'no admin recipe for a machine');
  }
});

test('AP5-05: a revoked machine token no longer passes the PoP challenge', { skip }, async () => {
  fromIp(13);
  const { token } = await machineToken({ withKey: true });

  const ok = await api('/hhttps/pop/challenge', { method: 'POST', body: { token } });
  assert.equal(ok.status, 200, ok.text);
  assert.equal(typeof ok.json.challenge, 'string');

  const rev = await api('/hhttps/revoke', { method: 'POST', body: { token } });
  assert.equal(rev.status, 200, rev.text);

  const after = await api('/hhttps/pop/challenge', { method: 'POST', body: { token } });
  assert.equal(after.status, 401, after.text);
  assert.equal(after.json.error, 'token_invalid');
});

test('AP5-23: logo_url / impressum_url are validated server-side on POST and PATCH', { skip }, async () => {
  fromIp(14);
  const { token, userId } = await portalAdmin('w2ap5-url');
  const base = { name: 'URL Check', homepage_url: 'https://example.org',
    redirect_uris: ['https://example.org/cb'], contact_email: 'ops@example.org' };

  for (const impressum of ['javascript:alert(1)', 'http://evil.example/imp',
                           'data:text/html,x', 'not a url', 'https://' + 'a'.repeat(3000)]) {
    const r = await api('/hhttps/developers/clients', { method: 'POST', ...auth(token),
      body: { ...base, impressum_url: impressum } });
    assert.equal(r.status, 400, `${impressum} → ${r.text}`);
    assert.equal(r.json.error, 'invalid_impressum_url');
  }
  for (const logo of ['javascript:alert(1)', 'data:text/html,<script>',
                      'data:image/png;base64,' + 'A'.repeat(70_000)]) {
    const r = await api('/hhttps/developers/clients', { method: 'POST', ...auth(token),
      body: { ...base, impressum_url: 'https://example.org/imp', logo_url: logo } });
    assert.equal(r.status, 400, `${logo} → ${r.text}`);
    assert.equal(r.json.error, 'invalid_logo_url');
  }
  // nothing of that reached the database
  assert.equal((await sql('SELECT 1 FROM oauth_clients WHERE owner_user_id = $1', [userId])).length, 0);

  const cid = await seedClient(userId);
  const bad = await api(`/hhttps/developers/clients/${cid}`, { method: 'PATCH', ...auth(token),
    body: { impressum_url: 'javascript:alert(1)' } });
  assert.equal(bad.status, 400, bad.text);
  assert.equal(bad.json.error, 'invalid_impressum_url');
  const good = await api(`/hhttps/developers/clients/${cid}`, { method: 'PATCH', ...auth(token),
    body: { logo_url: 'data:image/png;base64,iVBORw0KGgo=' } });
  assert.equal(good.status, 200, good.text);
});

test('AP5-07: PATCH clears description and logo_url on null — null is not "leave unchanged"',
  { skip }, async () => {
  fromIp(15);
  const { token, userId } = await portalAdmin('w2ap5-clear');
  const cid = await seedClient(userId, { description: 'old text', logo_url: 'https://example.org/l.png' });

  const r = await api(`/hhttps/developers/clients/${cid}`, { method: 'PATCH', ...auth(token),
    body: { description: null, logo_url: null } });
  assert.equal(r.status, 200, r.text);
  const [row] = await sql('SELECT description, logo_url, name FROM oauth_clients WHERE client_id = $1', [cid]);
  assert.equal(row.description, null, 'description cleared');
  assert.equal(row.logo_url, null, 'logo_url cleared');
  assert.equal(row.name, 'W2 AP5 Platform', 'an omitted field stays untouched');

  // undefined still means "leave unchanged"
  await api(`/hhttps/developers/clients/${cid}`, { method: 'PATCH', ...auth(token),
    body: { description: 'back again' } });
  const u = await api(`/hhttps/developers/clients/${cid}`, { method: 'PATCH', ...auth(token),
    body: { name: 'Renamed' } });
  assert.equal(u.status, 200, u.text);
  const [row2] = await sql('SELECT description, name FROM oauth_clients WHERE client_id = $1', [cid]);
  assert.equal(row2.description, 'back again');
  assert.equal(row2.name, 'Renamed');
});

test('AP5-20: PATCH is refused during review and drops a verified platform back to unverified',
  { skip }, async () => {
  fromIp(16);
  const { token, userId } = await portalAdmin('w2ap5-toctou');

  const reviewing = await seedClient(userId, { verification_status: 'pending_review' });
  const blocked = await api(`/hhttps/developers/clients/${reviewing}`, { method: 'PATCH',
    ...auth(token), body: { name: 'Sneaky Rename' } });
  assert.equal(blocked.status, 409, blocked.text);
  assert.equal(blocked.json.error, 'wrong_state');
  const [still] = await sql('SELECT name FROM oauth_clients WHERE client_id = $1', [reviewing]);
  assert.equal(still.name, 'W2 AP5 Platform', 'the reviewed record did not move');

  const live = await seedClient(userId, { verification_status: 'verified' });
  const changed = await api(`/hhttps/developers/clients/${live}`, { method: 'PATCH',
    ...auth(token), body: { redirect_uris: ['https://example.org/other-cb'] } });
  assert.equal(changed.status, 200, changed.text);
  assert.equal(changed.json.downgraded, true, 'the owner is told the badge is gone');
  assert.equal(await statusOf(live), 'unverified');

  // a no-op edit of a verified platform keeps the badge
  const live2 = await seedClient(userId, { verification_status: 'verified' });
  const noop = await api(`/hhttps/developers/clients/${live2}`, { method: 'PATCH',
    ...auth(token), body: { description: 'only the description' } });
  assert.equal(noop.status, 200, noop.text);
  assert.equal(noop.json.downgraded, false);
  assert.equal(await statusOf(live2), 'verified');
});

test('AP5-08: approve/reject/suspend enforce the state machine (409 wrong_state)', { skip }, async () => {
  fromIp(17);
  const { token, userId } = await portalAdmin('w2ap5-fsm');

  const unverified = await seedClient(userId, { verification_status: 'unverified' });
  const rej = await api(`/hhttps/admin/clients/${unverified}/reject`, { method: 'POST',
    ...auth(token), body: { reason: 'nope' } });
  assert.equal(rej.status, 409, rej.text);
  assert.equal(rej.json.error, 'wrong_state');
  assert.deepEqual(rej.json.allowed, ['pending_review']);
  const [row] = await sql(
    'SELECT verification_status, rejection_reason FROM oauth_clients WHERE client_id = $1', [unverified]);
  assert.equal(row.verification_status, 'unverified', 'reject did not overwrite the state');
  assert.equal(row.rejection_reason, null, '…nor stamp a reason on it');

  // suspend may leave 'unverified', but not a rejected or an already suspended client
  const susp = await api(`/hhttps/admin/clients/${unverified}/suspend`, { method: 'POST',
    ...auth(token), body: { reason: 'abuse report' } });
  assert.equal(susp.status, 200, susp.text);
  assert.equal(await statusOf(unverified), 'suspended');
  const again = await api(`/hhttps/admin/clients/${unverified}/suspend`, { method: 'POST',
    ...auth(token), body: { reason: 'abuse report' } });
  assert.equal(again.status, 409, again.text);

  const rejected = await seedClient(userId, { verification_status: 'rejected' });
  for (const action of ['approve', 'reject', 'suspend']) {
    const r = await api(`/hhttps/admin/clients/${rejected}/${action}`, { method: 'POST',
      ...auth(token), body: { reason: 'x' } });
    assert.equal(r.status, 409, `${action} → ${r.text}`);
    assert.equal(r.json.current, 'rejected');
  }

  const pending = await seedClient(userId, { verification_status: 'pending_review' });
  const ok = await api(`/hhttps/admin/clients/${pending}/reject`, { method: 'POST',
    ...auth(token), body: { reason: 'incomplete impressum' } });
  assert.equal(ok.status, 200, ok.text);
  assert.equal(await statusOf(pending), 'rejected');
});

test('AP5-06: Delete accepts exactly email_pending — anything else is 409', { skip }, async () => {
  fromIp(18);
  const { token, userId } = await portalAdmin('w2ap5-del');

  const unverified = await seedClient(userId, { verification_status: 'unverified' });
  const no = await api(`/hhttps/developers/clients/${unverified}`, { method: 'DELETE', ...auth(token) });
  assert.equal(no.status, 409, no.text);
  assert.equal(no.json.error, 'cannot_delete');
  assert.equal(await statusOf(unverified), 'unverified');

  const pending = await seedClient(userId, { verification_status: 'email_pending',
    email_verified_at: null, email_token: rnd(), email_token_expires_at: new Date(Date.now() + 3600_000) });
  const yes = await api(`/hhttps/developers/clients/${pending}`, { method: 'DELETE', ...auth(token) });
  assert.equal(yes.status, 200, yes.text);
  assert.equal(await statusOf(pending), undefined, 'row gone');
});

test('AP5-09: a non-numeric ?days never reaches Postgres — the request answers instead of hanging',
  { skip }, async () => {
  fromIp(19);
  const { token, userId } = await portalAdmin('w2ap5-days');
  const cid = await seedClient(userId);

  for (const [q, expected] of [['abc', 30], ['', 30], ['-5', 1], ['1000', 90], ['7', 7]]) {
    const r = await api(`/hhttps/developers/clients/${cid}/stats?days=${encodeURIComponent(q)}`, auth(token));
    assert.equal(r.status, 200, `days=${q} → ${r.text}`);
    assert.equal(r.json.days, expected, `days=${q}`);
  }
  // the server is still alive and the route still answers afterwards
  const alive = await api('/hhttps/info');
  assert.equal(alive.status, 200);
});

test('AP5-31: two DNS checks in a row are refused by the per-client minimum interval', { skip }, async () => {
  fromIp(20);
  const { token, userId } = await portalAdmin('w2ap5-dns');
  const cid = await seedClient(userId, { homepage_url: 'https://invalid-hhttps-test.example' });

  const first = await api(`/hhttps/developers/clients/${cid}/dns-check`, { method: 'POST', ...auth(token) });
  assert.equal(first.status, 200, first.text);          // resolves or fails, but it ANSWERS
  const [row] = await sql('SELECT dns_last_checked_at FROM oauth_clients WHERE client_id = $1', [cid]);
  assert.ok(row.dns_last_checked_at, 'the attempt was recorded');

  const second = await api(`/hhttps/developers/clients/${cid}/dns-check`, { method: 'POST', ...auth(token) });
  assert.equal(second.status, 429, second.text);
  assert.equal(second.json.error, 'dns_check_too_soon');
  assert.ok(second.json.retry_after > 0);
});

test('AP5-29: unconfirmed WP-plugin registrations per site apex are capped', { skip }, async () => {
  fromIp(21);
  const apex = `wp-ap5-${rnd()}.example`;
  const body = (n) => ({ site_name: `WP Site ${n}`, homepage_url: `https://${apex}`,
    redirect_uri: `https://${apex}/wp-json/hhttps/callback`, contact_email: `wp${n}@${apex}` });

  for (let i = 0; i < 3; i++) {
    const r = await api('/hhttps/plugin/register', { method: 'POST', body: body(i) });
    assert.equal(r.status, 200, r.text);
    assert.equal(r.json.success, true);
    clientIds.add(r.json.client_id);
  }
  const over = await api('/hhttps/plugin/register', { method: 'POST', body: body(3) });
  assert.equal(over.status, 429, over.text);
  assert.equal(over.json.error, 'too_many_pending');
  assert.equal((await sql(
    `SELECT COUNT(*)::int n FROM oauth_clients WHERE homepage_url = $1`, [`https://${apex}`]))[0].n, 3,
    'the refused registration wrote no row');

  // a different apex is unaffected by another site's backlog
  const otherApex = `wp-ap5-${rnd()}.example`;
  const other = await api('/hhttps/plugin/register', { method: 'POST', body: {
    site_name: 'Other', homepage_url: `https://${otherApex}`,
    redirect_uri: `https://${otherApex}/cb`, contact_email: `a@${otherApex}` } });
  assert.equal(other.status, 200, other.text);
  clientIds.add(other.json.client_id);
});

test('AP5-30: /hhttps/stats is served from a cache and says so', { skip }, async () => {
  fromIp(22);
  const first = await api('/hhttps/stats');
  assert.equal(first.status, 200, first.text);
  assert.match(first.headers.get('cache-control') || '', /public, max-age=[36]0/);
  const before = first.json.stats.machineOperators;
  assert.equal(typeof before, 'number');
  assert.equal(typeof first.json.stats.registeredWebhooks, 'number', 'webhooks are COUNTed, not listed');
  assert.ok(!first.text.includes('"secret"'), 'no webhook secret leaks into the public stats');

  // a write that the uncached route would have picked up immediately
  const opId = 'op-w2ap5-cache-' + rnd();
  await sql(`INSERT INTO machine_operators (operator_id, operator_name, purpose, contact_email, api_key_hash)
             VALUES ($1, 'Cache Probe', 'welle-2 ap5', 'probe@example.org', $2)`,
    [opId, crypto.randomBytes(16).toString('hex')]);
  operatorIds.add(opId);

  const second = await api('/hhttps/stats');
  assert.equal(second.status, 200, second.text);
  assert.equal(second.json.stats.machineOperators, before,
    'the second call within the TTL came from the cache, not from eight fresh queries');
});

test('AP5-10: /hhttps/whoami describes the signed-in portal user', { skip }, async () => {
  fromIp(23);
  const { token, userId } = await portalAdmin('w2ap5-who');
  const r = await api('/hhttps/whoami', auth(token));
  assert.equal(r.status, 200, r.text);
  assert.equal(r.json.user_id ?? r.json.userId, userId);
  assert.equal((await api('/hhttps/whoami')).status, 401, 'anonymous → 401');
});
