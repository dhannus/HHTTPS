// Review 2026-09, Welle 3 — AP5 integration tests against a booted server.js.
//
//   AP5-12  /hhttps/webhooks/verify answers 400 for non-string input (was 500)
//   AP5-14  homepage_url must really be HTTPS, in BOTH registration paths
//   AP5-25  /hhttps/whoami hands the make-admin recipe only to admins (or at
//           bootstrap, when there are no admins at all)
//   AP5-34  /hhttps/admin/clients pages, and says how many rows there are
//   AP5-38  one registration rule per door: the plugin's redirect check is the
//           portal's, and client_ids come from one generator
//   AP5-46  the plugin / PoP routes still answer after the mounts moved out of
//           main()
import test from 'node:test';
import assert from 'node:assert/strict';
import { startServer, pgAvailable } from '../helpers/server.mjs';
import { closeDb, sql } from '../helpers/db.mjs';
import { rnd, freshEmail, verifyEmail, createTracker } from '../helpers/identity-flow.mjs';

const skip = !pgAvailable() && 'TEST_PG_HOST not set';

let srv;
const track = createTracker();
const clientIds = new Set();
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
  if (adminIds.size) await sql('DELETE FROM admins WHERE user_id = ANY($1)', [[...adminIds]]);
  await track.cleanup();
  await srv.stop();
  await closeDb();
});

const auth = (token) => ({ headers: { authorization: `Bearer ${token}` } });

// Every limiter keys on req.ip behind `trust proxy 1` — each test brings its
// own client address so one case cannot exhaust another's budget.
let clientIp = '10.93.0.1';
const api = (p, opts = {}) =>
  srv.api(p, { ...opts, headers: { 'x-forwarded-for': clientIp, ...(opts.headers || {}) } });
const fromIp = (last) => { clientIp = `10.93.0.${last}`; };
const ipSrv = { api: (p, opts) => api(p, opts) };

/** e-mail-verified sign-in; `admin: true` also grants admin rights. */
async function signIn(tag, { admin = false } = {}) {
  const { sessionId, userId } = await verifyEmail(ipSrv, freshEmail(tag), undefined, track);
  if (admin) {
    await sql(`INSERT INTO admins (user_id, note) VALUES ($1, 'welle-3 ap5 test')
               ON CONFLICT (user_id) DO NOTHING`, [userId]);
    adminIds.add(userId);
  }
  const r = await api('/hhttps/role/declare', { method: 'POST', body: { sessionId } });
  assert.equal(r.status, 200, r.text);
  return { userId, sessionId, token: r.json.hhttps.token };
}

// ───────────────────────────────────────────────────────────────────────────

test('AP5-12: /hhttps/webhooks/verify rejects non-string input instead of throwing a 500',
  { skip }, async () => {
  fromIp(11);
  const good = { payload: '{"a":1}', signature: 'sha256=deadbeef', secret: 's'.repeat(32) };
  for (const bad of [{ payload: { a: 1 } }, { signature: 42 }, { secret: ['x'] },
                     { payload: null }, { payload: 7 }, { signature: {} }]) {
    const r = await api('/hhttps/webhooks/verify', { method: 'POST', body: { ...good, ...bad } });
    assert.equal(r.status, 400, `${JSON.stringify(bad)} → ${r.status} ${r.text}`);
  }
  // a missing field is still a 400, and an empty body no longer throws
  assert.equal((await api('/hhttps/webhooks/verify', { method: 'POST', body: {} })).status, 400);
  // the honest case still works, and the signature really is checked
  const ok = await api('/hhttps/webhooks/verify', { method: 'POST', body: good });
  assert.equal(ok.status, 200, ok.text);
  assert.equal(ok.json.valid, false);
  const roundTrip = await api('/hhttps/webhooks/verify', { method: 'POST',
    body: { ...good, signature: ok.json.expected } });
  assert.equal(roundTrip.json.valid, true);
});

test('AP5-14/AP5-38: the plugin door applies the portal\'s rules for homepage and redirect',
  { skip }, async () => {
  fromIp(12);
  const apex = `wp-ap5w3-${rnd()}.example`;
  const base = { site_name: 'W3 Site', homepage_url: `https://${apex}`,
    redirect_uri: `https://${apex}/cb`, contact_email: `a@${apex}` };

  // AP5-14: "must be a valid HTTPS URL" now means what it says.
  for (const homepage of [`http://${apex}`, `ftp://${apex}`, 'https://localhost']) {
    const r = await api('/hhttps/plugin/register', { method: 'POST',
      body: { ...base, homepage_url: homepage, redirect_uri: `${homepage}/cb` } });
    assert.equal(r.status, 400, `${homepage} → ${r.text}`);
    assert.equal(r.json.error, 'invalid_homepage');
  }
  // AP5-38: the plugin used to accept ANY scheme on localhost and the portal
  // only https/http-localhost — one rule now, and it is the stricter one.
  const badRedirect = await api('/hhttps/plugin/register', { method: 'POST',
    body: { ...base, redirect_uri: `https://${apex}/cb#frag` } });
  assert.equal(badRedirect.status, 400, badRedirect.text);
  assert.equal(badRedirect.json.error, 'invalid_redirect_uri');

  // AP5-46: the route is mounted outside main() and still answers.
  const good = await api('/hhttps/plugin/register', { method: 'POST', body: base });
  assert.equal(good.status, 200, good.text);
  clientIds.add(good.json.client_id);
  assert.match(good.json.client_id, /^wp-w3-site-[A-Za-z0-9_-]{8}$/, 'one client-id generator');
  assert.equal(good.json.expected_host, `_hhttps-verify.${apex}`);

  const status = await api(`/hhttps/plugin/status/${good.json.client_id}`);
  assert.equal(status.status, 200, status.text);
  assert.equal(status.json.expected_host, `_hhttps-verify.${apex}`);
});

test('AP5-14: the portal door rejects a non-HTTPS homepage too', { skip }, async () => {
  fromIp(13);
  const { token } = await signIn('w3ap5-home', { admin: true });
  const body = { name: 'W3 Portal Platform', homepage_url: 'http://example.org',
    redirect_uris: ['https://example.org/cb'], contact_email: 'ops@example.org' };
  const r = await api('/hhttps/developers/clients', { method: 'POST', ...auth(token), body });
  assert.equal(r.status, 400, r.text);
  assert.equal(r.json.error, 'invalid_homepage');
  if (r.json.client_id) clientIds.add(r.json.client_id);
});

test('AP5-25: /hhttps/whoami hands the make-admin recipe to admins only', { skip }, async () => {
  fromIp(14);
  // There is at least one admin row in the DB by now, so a plain user is not
  // in the bootstrap case and must not see a server filesystem path.
  const { token: adminToken } = await signIn('w3ap5-who-a', { admin: true });
  const { token: userToken }  = await signIn('w3ap5-who-u');

  const asAdmin = await api('/hhttps/whoami', auth(adminToken));
  assert.equal(asAdmin.status, 200, asAdmin.text);
  assert.equal(asAdmin.json.is_admin, true);
  assert.ok(asAdmin.json.grant_admin_command, 'an admin still gets the recipe');

  const asUser = await api('/hhttps/whoami', auth(userToken));
  assert.equal(asUser.status, 200, asUser.text);
  assert.equal(asUser.json.is_admin, false);
  assert.equal(asUser.json.grant_admin_command, undefined);
  assert.equal(asUser.text.includes('/var/www/'), false, 'no server path for a non-admin');
  // everything else about the answer is unchanged
  assert.ok(asUser.json.user_id);
  assert.ok(asUser.json.portal_access);
  assert.ok(asUser.json.identity);
});

test('AP5-34: /hhttps/admin/clients pages and reports the real total', { skip }, async () => {
  fromIp(15);
  const { token, userId } = await signIn('w3ap5-page', { admin: true });
  const made = [];
  for (let i = 0; i < 3; i++) {
    const clientId = `w3ap5-${rnd()}`;
    await sql(
      `INSERT INTO oauth_clients
         (client_id, name, homepage_url, redirect_uris, allowed_scopes, owner_user_id,
          verification_status, is_active)
       VALUES ($1, $2, 'https://example.org', '["https://example.org/cb"]', '["openid"]',
               $3, 'unverified', TRUE)`,
      [clientId, `W3 Paged ${i}`, userId]);
    clientIds.add(clientId);
    made.push(clientId);
  }

  const all = await api('/hhttps/admin/clients', auth(token));
  assert.equal(all.status, 200, all.text);
  assert.equal(all.json.limit, 200, 'the default window is the old LIMIT 200');
  assert.equal(all.json.offset, 0);
  assert.equal(typeof all.json.total, 'number');
  assert.equal(all.json.has_more, all.json.offset + all.json.clients.length < all.json.total);

  const first = await api('/hhttps/admin/clients?limit=1', auth(token));
  assert.equal(first.json.clients.length, 1);
  assert.equal(first.json.has_more, first.json.total > 1);
  const second = await api('/hhttps/admin/clients?limit=1&offset=1', auth(token));
  assert.equal(second.json.clients.length, 1);
  assert.notEqual(second.json.clients[0].client_id, first.json.clients[0].client_id);
  assert.equal(second.json.total, first.json.total, 'total does not depend on the window');

  // a filtered count is the count of the filter, not of the table
  const filtered = await api('/hhttps/admin/clients?status=unverified&limit=1', auth(token));
  assert.equal(filtered.status, 200, filtered.text);
  assert.ok(filtered.json.total >= made.length);
  assert.ok(filtered.json.total <= all.json.total);
  assert.equal(filtered.json.clients[0].verification_status, 'unverified');

  // nonsense paging falls back to the defaults instead of reaching Postgres
  for (const q of ['limit=abc', 'offset=abc', 'limit=-3', 'limit=99999']) {
    const r = await api(`/hhttps/admin/clients?${q}`, auth(token));
    assert.equal(r.status, 200, `${q} → ${r.text}`);
    assert.ok(r.json.limit >= 1 && r.json.limit <= 500, `${q} → limit ${r.json.limit}`);
    assert.ok(r.json.offset >= 0);
  }
});
