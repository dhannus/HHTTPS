// Review 2026-09, Welle 2 — AP4 unit tests (no database).
//
//   AP4-24  only documented POSITIVE terminal states mean "presentation valid";
//           claims come from the verified disclosure fields, not any nested key
//   AP4-09  negative/gone sessions are terminal `failed`, not endless `pending`
//   AP4-10  a 401 from EUDIPLO invalidates the cached client-credentials token
//   AP4-38  the session path is auto-discovered ONCE, not on every poll
//   AP4-39  every upstream fetch is bounded by a timeout
//   AP4-28  EUDI_DEBUG never prints the wallet response body, and is off in production
//   AP4-08  a second concurrent status poll does not trigger a second upgrade
//   AP4-37  /eudi/*/request verifies the HHTTPS session BEFORE creating an
//           EUDIPLO session, and the transaction store is bounded
import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import http from 'node:http';
import { startEudiploStub, startInternalStub } from '../helpers/eudiplo-stub.mjs';

let eudiplo;
let modSeq = 0;

/** Fresh backend-client instance (module-level caches reset, env re-read). */
async function freshBackendClient(env = {}) {
  const prev = {};
  for (const [k, v] of Object.entries(env)) { prev[k] = process.env[k]; process.env[k] = v; }
  process.env.EUDIPLO_BASE_URL = eudiplo.url;
  process.env.EUDIPLO_CLIENT_SECRET = 'stub-secret';
  const mod = await import(`../../eudi-verifier/backend-client.js?v=${++modSeq}`);
  return { mod, restore: () => { for (const [k, v] of Object.entries(prev)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } } };
}

function resetStub() {
  eudiplo.state.tokenCalls = 0;
  eudiplo.state.sessionGets = 0;
  eudiplo.state.offerCalls = 0;
  eudiplo.state.issuerOffers.length = 0;
  eudiplo.state.rejectTokens = new Set();
  eudiplo.state.session = { status: 200, body: { status: 'pending' } };
  eudiplo.state.hangSession = false;
  eudiplo.state.onlyFirstPath = false;
}

test.before(async () => { eudiplo = await startEudiploStub(); });
test.after(async () => { await eudiplo.stop(); });

// ─── AP4-24 / AP4-09: terminal-state classification ──────────────────────────
test('AP4-24: "submitted" is not a positive terminal state and a stray age_over_* key is not a proof', async () => {
  resetStub();
  const { mod, restore } = await freshBackendClient({ EUDIPLO_SESSION_PATH: '/verifier/session/{id}' });
  try {
    assert.equal(mod.sessionLooksDone({ status: 'submitted' }), false, '"submitted" is wallet-posted, not validated');
    assert.equal(mod.sessionLooksDone({ status: 'pending', foo: { age_over_18: true } }), false,
      'an explicit non-terminal status wins over a nested claim');
    assert.equal(mod.sessionLooksDone({ anything: { age_over_18: true } }), false,
      'an arbitrary nested age_over_* key is not a disclosure field');
    assert.equal(mod.sessionLooksDone({ status: 'verified' }), true);
    assert.equal(mod.sessionLooksDone({ credentials: { age_over_18: true } }), true,
      'a verified disclosure field without a status is done');
    // Claims are read from the disclosure field, not from the whole body.
    assert.deepEqual(mod.extractVerifiedAgeClaims({ status: 'pending', junk: { age_over_18: true } }), {});
    assert.deepEqual(mod.extractVerifiedAgeClaims({ status: 'verified', claims: { age_over_18: true } }), { age_over_18: true });
  } finally { restore(); }
});

test('AP4-09: negative terminal states and a vanished session end the poll with "failed"', async () => {
  resetStub();
  const { mod, restore } = await freshBackendClient({ EUDIPLO_SESSION_PATH: '/verifier/session/{id}' });
  try {
    assert.equal(mod.sessionLooksFailed({ status: 'rejected' }), 'rejected');
    assert.equal(mod.sessionLooksFailed({ status: 'expired' }), 'expired');
    assert.equal(mod.sessionLooksFailed({ error: 'presentation_invalid' }), 'presentation_invalid');
    assert.equal(mod.sessionLooksFailed({ status: 'pending' }), null);

    eudiplo.state.session = { status: 200, body: { status: 'failed' } };
    assert.deepEqual(await mod.pollWalletResponse('tx-failed'), { status: 'failed', reason: 'failed' });

    // A 404 BEFORE the session was ever seen is still "pending" (not created yet)…
    eudiplo.state.session = { status: 404, body: {} };
    assert.deepEqual(await mod.pollWalletResponse('tx-gone'), { status: 'pending' });
    // …but after a successful poll it means the session is gone upstream.
    eudiplo.state.session = { status: 200, body: { status: 'pending' } };
    assert.deepEqual(await mod.pollWalletResponse('tx-gone'), { status: 'pending' });
    eudiplo.state.session = { status: 404, body: {} };
    assert.deepEqual(await mod.pollWalletResponse('tx-gone'), { status: 'failed', reason: 'session_gone' });
  } finally { restore(); }
});

// ─── AP4-10 ──────────────────────────────────────────────────────────────────
test('AP4-10: a 401 from EUDIPLO drops the cached token and the call is retried once', async () => {
  resetStub();
  const { mod, restore } = await freshBackendClient({ EUDIPLO_SESSION_PATH: '/verifier/session/{id}' });
  try {
    assert.deepEqual(await mod.pollWalletResponse('tx-a'), { status: 'pending' });
    assert.equal(eudiplo.state.tokenCalls, 1, 'one token fetch so far');
    // The cached token is no longer accepted upstream (secret rotated / restart).
    eudiplo.state.rejectTokens = new Set(['tok-1']);
    assert.deepEqual(await mod.pollWalletResponse('tx-a'), { status: 'pending' },
      'the retry with a fresh token succeeds');
    assert.equal(eudiplo.state.tokenCalls, 2, 'the cache was invalidated and a new token fetched');
  } finally { restore(); }
});

// ─── AP4-38 ──────────────────────────────────────────────────────────────────
test('AP4-38: the session path is discovered once — later polls issue a single GET', async () => {
  resetStub();
  eudiplo.state.session = { status: 404, body: {} };        // nothing answers 2xx yet
  const { mod, restore } = await freshBackendClient({ EUDIPLO_SESSION_PATH: '' });
  try {
    assert.deepEqual(await mod.pollWalletResponse('tx-d'), { status: 'pending' });
    const afterFirst = eudiplo.state.sessionGets;
    assert.ok(afterFirst >= 2, `the first poll probes the candidates (${afterFirst} GETs)`);
    await mod.pollWalletResponse('tx-d');
    assert.equal(eudiplo.state.sessionGets - afterFirst, 1,
      'the second poll hits the resolved path only (was: 3 probes per poll, forever)');
  } finally { restore(); }
});

// ─── AP4-39 ──────────────────────────────────────────────────────────────────
test('AP4-39: an upstream call that never answers is aborted by the fetch timeout', async () => {
  resetStub();
  const { mod, restore } = await freshBackendClient({
    EUDIPLO_SESSION_PATH: '/verifier/session/{id}', EUDIPLO_FETCH_TIMEOUT_MS: '300'
  });
  try {
    eudiplo.state.hangSession = true;
    const started = Date.now();
    await assert.rejects(() => mod.pollWalletResponse('tx-hang'));
    assert.ok(Date.now() - started < 5000, 'aborted long before undici\'s ~300 s default');
  } finally { eudiplo.state.hangSession = false; restore(); }
});

// ─── AP4-28 ──────────────────────────────────────────────────────────────────
test('AP4-28: EUDI_DEBUG never logs the wallet response body and is ignored in production', async () => {
  resetStub();
  eudiplo.state.session = { status: 200, body: { status: 'verified', claims: { age_over_18: true, given_name: 'SECRET-PII' } } };
  const lines = [];
  const realLog = console.log;
  console.log = (...a) => lines.push(a.join(' '));
  try {
    const dev = await freshBackendClient({ EUDI_DEBUG: '1', NODE_ENV: 'test', EUDIPLO_SESSION_PATH: '/verifier/session/{id}' });
    await dev.mod.pollWalletResponse('tx-dbg');
    dev.restore();
    const devLog = lines.join('\n');
    assert.ok(devLog.includes('[EUDI-DEBUG]'), 'debug logging is active in development');
    assert.ok(!devLog.includes('SECRET-PII'), 'the wallet response body is never printed');

    lines.length = 0;
    const prod = await freshBackendClient({ EUDI_DEBUG: '1', NODE_ENV: 'production', EUDIPLO_SESSION_PATH: '/verifier/session/{id}' });
    await prod.mod.pollWalletResponse('tx-dbg-prod');
    prod.restore();
    assert.equal(lines.join('\n').includes('[EUDI-DEBUG]'), false, 'EUDI_DEBUG is ignored in production');
  } finally { console.log = realLog; }
});

// ─── AP4-08 / AP4-37: the router ─────────────────────────────────────────────
async function mountRouter(sessions) {
  process.env.EUDIPLO_BASE_URL = eudiplo.url;
  process.env.EUDIPLO_CLIENT_SECRET = 'stub-secret';
  process.env.EUDIPLO_SESSION_PATH = '/verifier/session/{id}';
  process.env.EUDI_VERIFIER_SECRET = 'unit-test-secret';
  const { createEudiVerifierRouter } = await import(`../../eudi-verifier/index.js?v=${++modSeq}`);
  const app = express();
  app.use('/eudi', createEudiVerifierRouter({ getSession: async (id) => sessions.get(id) || null }));
  const server = http.createServer(app);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const api = async (p, init) => {
    const res = await fetch(base + p, init);
    return { status: res.status, json: await res.json().catch(() => null) };
  };
  return { api, stop: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }) };
}

test('AP4-37: /eudi/age/request checks the HHTTPS session before creating an EUDIPLO session', async () => {
  resetStub();
  const sessions = new Map([['live-1', { sessionId: 'live-1', verified: true }]]);
  const r = await mountRouter(sessions);
  try {
    const miss = await r.api('/eudi/age/request', { method: 'POST',
      headers: { 'content-type': 'application/json' }, body: JSON.stringify({ hhttpsSession: 'nope' }) });
    assert.equal(miss.status, 404, 'unknown session refused');
    assert.equal(miss.json.error, 'session_not_found');
    assert.equal(eudiplo.state.offerCalls, 0, 'nothing was created upstream for an unknown session');

    const ok = await r.api('/eudi/age/request', { method: 'POST',
      headers: { 'content-type': 'application/json' }, body: JSON.stringify({ hhttpsSession: 'live-1' }) });
    assert.equal(ok.status, 200, JSON.stringify(ok.json));
    assert.equal(eudiplo.state.offerCalls, 1);
  } finally { await r.stop(); }
});

test('AP4-08: concurrent status polls trigger the age upgrade exactly once', async () => {
  resetStub();
  const internal = await startInternalStub({ delayMs: 150 });
  process.env.HHTTPS_INTERNAL_URL = internal.url;
  const sessions = new Map([['live-2', { sessionId: 'live-2', verified: true }]]);
  const r = await mountRouter(sessions);
  try {
    const start = await r.api('/eudi/age/request', { method: 'POST',
      headers: { 'content-type': 'application/json' }, body: JSON.stringify({ hhttpsSession: 'live-2' }) });
    assert.equal(start.status, 200, JSON.stringify(start.json));
    const { requestId } = start.json;

    eudiplo.state.session = { status: 200, body: { status: 'verified', claims: { age_over_18: true } } };
    const polls = await Promise.all([
      r.api(`/eudi/age/status/${requestId}`),
      r.api(`/eudi/age/status/${requestId}`),
      r.api(`/eudi/age/status/${requestId}`),
    ]);
    assert.equal(internal.state.calls.length, 1,
      `exactly one /hhttps/age/upgrade call (got ${internal.state.calls.length})`);
    assert.ok(polls.some((p) => p.json.status === 'verified'), 'the winning poll returns the result');
    assert.ok(polls.every((p) => ['verified', 'pending'].includes(p.json.status)));

    // Later polls are served from the cached terminal result — still one upgrade.
    const again = await r.api(`/eudi/age/status/${requestId}`);
    assert.equal(again.json.status, 'verified');
    assert.equal(internal.state.calls.length, 1);
  } finally { await r.stop(); await internal.stop(); delete process.env.HHTTPS_INTERNAL_URL; }
});

test('AP4-09: a failed EUDIPLO session is reported as terminal "failed" to the browser', async () => {
  resetStub();
  const internal = await startInternalStub();
  process.env.HHTTPS_INTERNAL_URL = internal.url;
  const sessions = new Map([['live-3', { sessionId: 'live-3', verified: true }]]);
  const r = await mountRouter(sessions);
  try {
    const start = await r.api('/eudi/eid/request', { method: 'POST',
      headers: { 'content-type': 'application/json' }, body: JSON.stringify({ hhttpsSession: 'live-3' }) });
    assert.equal(start.status, 200, JSON.stringify(start.json));
    eudiplo.state.session = { status: 200, body: { status: 'rejected' } };
    const poll = await r.api(`/eudi/eid/status/${start.json.requestId}`);
    assert.equal(poll.json.status, 'failed');
    assert.equal(poll.json.reason, 'rejected');
    assert.equal(internal.state.calls.length, 0, 'no eID upgrade for a rejected presentation');
  } finally { await r.stop(); await internal.stop(); delete process.env.HHTTPS_INTERNAL_URL; }
});

test('AP4-37: the transaction store is bounded — a full store refuses instead of growing', async () => {
  resetStub();
  process.env.EUDI_MAX_PENDING_TX = '2';
  const sessions = new Map([['live-4', { sessionId: 'live-4', verified: true }]]);
  const r = await mountRouter(sessions);
  try {
    const start = () => r.api('/eudi/age/request', { method: 'POST',
      headers: { 'content-type': 'application/json' }, body: JSON.stringify({ hhttpsSession: 'live-4' }) });
    assert.equal((await start()).status, 200);
    assert.equal((await start()).status, 200);
    const full = await start();
    assert.equal(full.status, 503, JSON.stringify(full.json));
    assert.equal(full.json.error, 'too_many_pending_verifications');
    assert.equal(eudiplo.state.offerCalls, 2, 'no third EUDIPLO session was created');
  } finally { await r.stop(); delete process.env.EUDI_MAX_PENDING_TX; }
});
