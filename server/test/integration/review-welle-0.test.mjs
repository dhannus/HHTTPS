// Review 2026-09, Welle 0 — integration tests against a booted server.js:
//   AP3-13  /hhttps/email/send rejects addresses the transport would read differently
//   AP5-16  /hhttps/webhooks requires an HHTTPS token, lists only own webhooks
//   AP1-22  the list never contains the HMAC secret
//   AP1-21  SSRF guard: private / loopback targets are rejected at registration
//   AP7     the Privacy-Pass module is gone; AP8-15 email-verify.html is gone
import test from 'node:test';
import assert from 'node:assert/strict';
import { startServer, pgAvailable } from '../helpers/server.mjs';
import { closeDb, sql } from '../helpers/db.mjs';
import { freshEmail, newSession, verifyEmail, createTracker } from '../helpers/identity-flow.mjs';

const skip = !pgAvailable() && 'TEST_PG_HOST not set';
let srv;
const track = createTracker();
const webhookIds = [];

test.before(async () => {
  if (skip) return;
  srv = await startServer({ env: { SMTP_HOST: '', SMTP_USER: '', SMTP_PASS: '' } });
});
test.after(async () => {
  if (skip) return;
  if (webhookIds.length) await sql(`DELETE FROM webhooks WHERE webhook_id = ANY($1)`, [webhookIds]);
  await track.cleanup();
  await srv.stop();
  await closeDb();
});

/** e-mail-verified session → HHTTPS access token via role/declare. */
async function userToken(tag) {
  const { sessionId, userId } = await verifyEmail(srv, freshEmail(tag), undefined, track);
  const r = await srv.api('/hhttps/role/declare', { method: 'POST', body: { sessionId } });
  assert.equal(r.status, 200, r.text);
  return { token: r.json.hhttps.token, userId };
}
const auth = (token) => ({ headers: { authorization: `Bearer ${token}` } });

test('AP3-13: /hhttps/email/send rejects an address with a comment paren (would go to evil.com but classify as official)', { skip }, async () => {
  const sessionId = await newSession(srv, {}, track);
  for (const email of ['x@evil.com(bundestag.de', 'x@evil.com＠bundestag.de', '"x"@bundestag.de']) {
    const r = await srv.api('/hhttps/email/send', { method: 'POST', body: { sessionId, email } });
    assert.equal(r.status, 400, `${email}: ${r.text}`);
  }
});

test('AP5-16: webhook routes require an HHTTPS token', { skip }, async () => {
  assert.equal((await srv.api('/hhttps/webhooks')).status, 401);
  assert.equal((await srv.api('/hhttps/webhooks', { method: 'POST', body: { url: 'https://example.org/h' } })).status, 401);
  assert.equal((await srv.api('/hhttps/webhooks/abc', { method: 'DELETE' })).status, 401);
});

test('AP1-21: SSRF guard rejects loopback / private / metadata / http-in-prod-style targets', { skip }, async () => {
  const { token } = await userToken('w0ssrf');
  for (const url of ['http://127.0.0.1:3000/x', 'https://localhost/x', 'https://10.0.0.5/x', 'https://169.254.169.254/latest', 'https://[::1]/x', 'https://user:pw@example.org/x', 'ftp://example.org/x', 'not a url']) {
    const r = await srv.api('/hhttps/webhooks', { method: 'POST', body: { url }, ...auth(token) });
    assert.equal(r.status, 400, `${url}: ${r.text}`);
  }
});

test('AP5-16 / AP1-22: register → secret once; list is owner-scoped and secret-free; delete is owner-scoped', { skip }, async () => {
  const a = await userToken('w0a');
  const b = await userToken('w0b');
  // 93.184.216.34 = example.org (public); a literal IP avoids DNS in the sandbox.
  const reg = await srv.api('/hhttps/webhooks', { method: 'POST', body: { url: 'https://93.184.216.34/hook', events: ['token.issued'] }, ...auth(a.token) });
  assert.equal(reg.status, 201, reg.text);
  const wh = reg.json.webhook;
  webhookIds.push(wh.id);
  assert.match(wh.secret, /^[0-9a-f]{64}$/, 'secret is returned exactly once at registration');

  const listA = await srv.api('/hhttps/webhooks', auth(a.token));
  assert.equal(listA.status, 200, listA.text);
  const mine = listA.json.webhooks.find(w => w.id === wh.id);
  assert.ok(mine, 'owner sees the webhook');
  assert.equal(mine.secret, undefined, 'list never contains the secret');
  assert.ok(!listA.text.includes(wh.secret), 'secret does not appear anywhere in the list response');

  const listB = await srv.api('/hhttps/webhooks', auth(b.token));
  assert.equal(listB.status, 200);
  assert.ok(!listB.json.webhooks.some(w => w.id === wh.id), 'another user does not see it');

  const delB = await srv.api(`/hhttps/webhooks/${wh.id}`, { method: 'DELETE', ...auth(b.token) });
  assert.equal(delB.status, 404, 'another user cannot delete it');
  const delA = await srv.api(`/hhttps/webhooks/${wh.id}`, { method: 'DELETE', ...auth(a.token) });
  assert.equal(delA.status, 200, delA.text);
  const rows = await sql(`SELECT 1 FROM webhooks WHERE webhook_id = $1`, [wh.id]);
  assert.equal(rows.length, 0);
});

test('AP7 / AP8-15: privacy-pass routes and the dead email-verify page are gone', { skip }, async () => {
  for (const p of ['/privacy-pass/', '/privacy-pass/keys', '/privacy-pass/token-request', '/email-verify.html', '/email-patch.js']) {
    const r = await srv.api(p);
    assert.equal(r.status, 404, p);
  }
});
