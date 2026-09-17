// Review 2026-09, Welle 3 — AP4 regression tests for the maintainability
// refactorings. These pin the CONTRACTS that the de-duplication must not move:
//
//   AP4-47 (#228)  one assertion module — the canonical byte string per endpoint
//                  is exactly what the three internal endpoints recompute, and
//                  the three canonicals stay mutually non-replayable
//   AP4-50 (#239)  one status handler for age/av/eid — same shapes as before
//   AP4-51 (#242)  one ensureConfig: an existing config is PATCHed for EVERY
//                  flavour (PID, AV, eID), not only for AV
//   AP4-52 (#245)  every EUDI/EUDIPLO env var the module reads is documented
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import express from 'express';
import http from 'node:http';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  canonicalAssertion, signAssertion, verifyAssertion, ASSERTION_KINDS,
  ASSERTION_MAX_AGE_MS, ASSERTION_CLOCK_SKEW_MS
} from '../../eudi-verifier/assertion.js';
import { startEudiploStub, startInternalStub } from '../helpers/eudiplo-stub.mjs';

const here      = dirname(fileURLToPath(import.meta.url));
const serverDir = join(here, '..', '..');

// ─── AP4-47 ──────────────────────────────────────────────────────────────────

test('AP4-47: the canonical of each endpoint is byte-for-byte the historical one', () => {
  const nonce = 'n-1', iat = 1_700_000_000_000;
  const ageOver = { age_over_16: true };   // 14/18 missing ⇒ must become false

  assert.equal(
    canonicalAssertion('age/upgrade', { sessionId: 's-1', ageOver, nonce, iat }),
    JSON.stringify({
      sessionId: 's-1',
      ageOver: { age_over_14: false, age_over_16: true, age_over_18: false },
      nonce, iat
    }));

  assert.equal(
    canonicalAssertion('age/direct', { ageOver, nonce, iat }),
    JSON.stringify({
      direct: true,
      ageOver: { age_over_14: false, age_over_16: true, age_over_18: false },
      nonce, iat
    }));

  assert.equal(
    canonicalAssertion('eid/upgrade', { sessionId: 's-1', nonce, iat }),
    JSON.stringify({ sessionId: 's-1', eidVerified: true, nonce, iat }));

  // A missing nonce/iat is `null`, never `undefined` (which JSON would drop).
  assert.equal(canonicalAssertion('eid/upgrade', { sessionId: 's-1' }),
    JSON.stringify({ sessionId: 's-1', eidVerified: true, nonce: null, iat: null }));
});

test('AP4-47: an assertion of one endpoint never verifies on another', () => {
  const secret = 'shared-secret';
  const nonce = crypto.randomUUID(), iat = Date.now();
  const ageOver = { age_over_18: true };

  const upgrade = signAssertion('age/upgrade', secret, { sessionId: 's', ageOver, nonce, iat });
  assert.ok(verifyAssertion('age/upgrade', secret, { sessionId: 's', ageOver, nonce, iat }, upgrade));
  assert.equal(verifyAssertion('age/direct', secret, { ageOver, nonce, iat }, upgrade), false,
    'the age/upgrade assertion must not pass at /hhttps/age/direct');
  assert.equal(verifyAssertion('eid/upgrade', secret, { sessionId: 's', nonce, iat }, upgrade), false);

  const eid = signAssertion('eid/upgrade', secret, { sessionId: 's', nonce, iat });
  assert.equal(verifyAssertion('age/upgrade', secret, { sessionId: 's', ageOver, nonce, iat }, eid), false);
});

test('AP4-47: verifyAssertion is false (not a throw) for a wrong secret, a tampered field or a short value', () => {
  const nonce = 'n', iat = Date.now();
  const payload = { sessionId: 's', ageOver: { age_over_18: true }, nonce, iat };
  const good = signAssertion('age/upgrade', 'secret-a', payload);

  assert.equal(verifyAssertion('age/upgrade', 'secret-b', payload, good), false, 'wrong secret');
  assert.equal(verifyAssertion('age/upgrade', 'secret-a',
    { ...payload, ageOver: { age_over_18: false } }, good), false, 'flipped claim');
  assert.equal(verifyAssertion('age/upgrade', 'secret-a', { ...payload, sessionId: 'other' }, good), false);
  // timingSafeEqual throws on differing lengths — the length guard must catch it.
  assert.equal(verifyAssertion('age/upgrade', 'secret-a', payload, 'short'), false);
  assert.equal(verifyAssertion('age/upgrade', 'secret-a', payload, undefined), false);
  assert.throws(() => signAssertion('nope', 's', {}), /unknown assertion kind/);
  assert.deepEqual(ASSERTION_KINDS, ['age/upgrade', 'age/direct', 'eid/upgrade']);
  assert.equal(ASSERTION_MAX_AGE_MS, 300_000);
  assert.equal(ASSERTION_CLOCK_SKEW_MS, 60_000);
});

test('AP4-47: server.js and the verifier use the SAME module — no second canonical is left', () => {
  const server = readFileSync(join(serverDir, 'server.js'), 'utf8');
  const router = readFileSync(join(serverDir, 'eudi-verifier', 'index.js'), 'utf8');
  // Strip comments: the endpoint docs legitimately SHOW the canonical structure.
  const code = (src) => src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
  for (const [name, src] of [['server.js', server], ['eudi-verifier/index.js', router]]) {
    const body = code(src);
    assert.equal(/eidVerified\s*:/.test(body), false, `${name} still builds an eid canonical by hand`);
    assert.equal(/age_over_14\s*:/.test(body), false, `${name} still builds an ageOver canonical by hand`);
  }
  // The verifier signs nothing itself any more.
  assert.equal(/createHmac/.test(code(router)), false, 'eudi-verifier/index.js still HMACs by hand');
  assert.match(server, /from '\.\/eudi-verifier\/assertion\.js'/);
  assert.match(router, /from '\.\/assertion\.js'/);
});

// ─── AP4-52 ──────────────────────────────────────────────────────────────────

test('AP4-52: every env var the eudi-verifier reads is documented in .env.example', () => {
  const env = readFileSync(join(serverDir, '.env.example'), 'utf8');
  const sources = ['index.js', 'backend-client.js', 'assertion.js']
    .map((f) => readFileSync(join(serverDir, 'eudi-verifier', f), 'utf8')).join('\n');
  const used = new Set([...sources.matchAll(/process\.env\.([A-Z0-9_]+)/g)].map((m) => m[1]));
  assert.ok(used.size >= 16, `expected the full EUDI env surface, found ${used.size}`);
  for (const name of used) {
    assert.ok(new RegExp(`^#?\\s*${name}=`, 'm').test(env) || new RegExp(`\\b${name}\\b`).test(env),
      `${name} is read by the eudi-verifier but missing from .env.example`);
  }
  // The two that make the flows fail closed must be there uncommented.
  assert.match(env, /^EUDI_VERIFIER_SECRET=/m);
  assert.match(env, /^EUDIPLO_CLIENT_SECRET=/m);
});

// ─── AP4-50 / AP4-51: against the EUDIPLO stub ───────────────────────────────

let eudiplo;
let modSeq = 0;
test.before(async () => { eudiplo = await startEudiploStub(); });
test.after(async () => { await eudiplo.stop(); });

function resetStub() {
  eudiplo.state.tokenCalls = 0;
  eudiplo.state.sessionGets = 0;
  eudiplo.state.offerCalls = 0;
  eudiplo.state.configPosts.length = 0;
  eudiplo.state.configPatches.length = 0;
  eudiplo.state.configCreateStatus = 201;
  eudiplo.state.issuerOffers.length = 0;
  eudiplo.state.rejectTokens = new Set();
  eudiplo.state.session = { status: 200, body: { status: 'pending' } };
  eudiplo.state.hangSession = false;
  eudiplo.state.onlyFirstPath = false;
}

async function freshBackendClient() {
  process.env.EUDIPLO_BASE_URL = eudiplo.url;
  process.env.EUDIPLO_CLIENT_SECRET = 'stub-secret';
  process.env.EUDIPLO_SESSION_PATH = '/verifier/session/{id}';
  return import(`../../eudi-verifier/backend-client.js?w3=${++modSeq}`);
}

test('AP4-51: an existing verifier config is PATCHed for PID, AV and eID alike', async () => {
  resetStub();
  eudiplo.state.configCreateStatus = 409;          // "already exists" for every flavour
  const bc = await freshBackendClient();

  await bc.initTransaction(18);
  await bc.initAvTransaction(16);
  await bc.initEidTransaction();

  const patched = eudiplo.state.configPatches.map((c) => c.id).sort();
  assert.deepEqual(patched, ['age-over-18', 'av-age-over-16', 'eid-identity'].sort(),
    'PID and eID used to reuse the stored (possibly trust-unbound) DCQL silently');
  for (const { body } of eudiplo.state.configPatches) {
    assert.ok(body.dcql_query, 'the PATCH carries the current DCQL');
    assert.ok(body.description, 'and the current description');
  }
  assert.equal(eudiplo.state.offerCalls, 3, 'each flavour still creates exactly one offer');
});

test('AP4-51: a config create that fails for another reason is an error, per flavour', async () => {
  resetStub();
  eudiplo.state.configCreateStatus = 500;
  const bc = await freshBackendClient();
  await assert.rejects(() => bc.initTransaction(18),   /EUDIPLO config create failed \(500\)/);
  await assert.rejects(() => bc.initAvTransaction(18), /EUDIPLO AV config create failed \(500\)/);
  await assert.rejects(() => bc.initEidTransaction(),  /EUDIPLO eid config create failed \(500\)/);
  assert.equal(eudiplo.state.offerCalls, 0, 'no offer is created for a broken config');
});

async function mountRouter(sessions) {
  process.env.EUDIPLO_BASE_URL = eudiplo.url;
  process.env.EUDIPLO_CLIENT_SECRET = 'stub-secret';
  process.env.EUDIPLO_SESSION_PATH = '/verifier/session/{id}';
  process.env.EUDI_VERIFIER_SECRET = 'w3-test-secret';
  const { createEudiVerifierRouter } = await import(`../../eudi-verifier/index.js?w3=${++modSeq}`);
  const cookies = [];
  const app = express();
  app.use('/eudi', createEudiVerifierRouter({
    getSession: async (id) => sessions.get(id) || null,
    setIdentityCookie: (_res, token) => cookies.push(token),
  }));
  const server = http.createServer(app);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const api = async (p, init) => {
    const res = await fetch(base + p, init);
    return { status: res.status, json: await res.json().catch(() => null) };
  };
  const post = (p, body) => api(p, { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { api, post, cookies,
    stop: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }) };
}

test('AP4-50: the merged status handler answers age, av and eid with their own shapes', async () => {
  resetStub();
  const internal = await startInternalStub();
  process.env.HHTTPS_INTERNAL_URL = internal.url;
  const sessions = new Map([['live', { sessionId: 'live', verified: true }]]);
  const r = await mountRouter(sessions);
  try {
    eudiplo.state.session = { status: 200, body: { status: 'verified', claims: { age_over_18: true } } };

    for (const kind of ['age', 'av']) {
      const start = await r.post(`/eudi/${kind}/request`, { hhttpsSession: 'live' });
      assert.equal(start.status, 200, JSON.stringify(start.json));
      const poll = await r.api(`/eudi/${kind}/status/${start.json.requestId}`);
      assert.equal(poll.json.status, 'verified', `${kind}: ${JSON.stringify(poll.json)}`);
      assert.equal(poll.json.ageGroup.id, 'adult', `${kind} reports the ageGroup`);
      assert.ok(poll.json.hhttps.token, `${kind} passes the reissued token through`);
      assert.equal(poll.json.eudi, undefined, `${kind} has no eudi key`);
    }

    const eid = await r.post('/eudi/eid/request', { hhttpsSession: 'live' });
    const poll = await r.api(`/eudi/eid/status/${eid.json.requestId}`);
    assert.equal(poll.json.status, 'verified', JSON.stringify(poll.json));
    assert.deepEqual(poll.json.eudi, { verified: true, method: 'eudi-eid' });
    assert.equal(poll.json.ageGroup, undefined, 'eID is orthogonal to age');

    assert.equal(r.cookies.length, 3, 'every verified poll mirrors the token into the browser cookie');
    assert.deepEqual(internal.state.calls.map((c) => c.path).sort(),
      ['/hhttps/age/upgrade', '/hhttps/age/upgrade', '/hhttps/eid/upgrade']);
    // AP4-47: the signature the internal endpoints will recompute.
    for (const call of internal.state.calls) {
      const kind = call.path.replace('/hhttps/', '');
      assert.ok(verifyAssertion(kind, 'w3-test-secret', call.body, call.body.assertion),
        `${kind}: the signed canonical matches assertion.js`);
    }
  } finally { await r.stop(); await internal.stop(); delete process.env.HHTTPS_INTERNAL_URL; }
});

test('AP4-50/AP4-14: a presentation without any disclosed age claim fails terminally and is not re-polled', async () => {
  resetStub();
  const internal = await startInternalStub();
  process.env.HHTTPS_INTERNAL_URL = internal.url;
  const sessions = new Map([['live', { sessionId: 'live', verified: true }]]);
  const r = await mountRouter(sessions);
  try {
    // A terminal session that discloses only `false` booleans proves nothing.
    eudiplo.state.session = { status: 200, body: { status: 'verified', claims: { age_over_18: false } } };
    const start = await r.post('/eudi/age/request', { hhttpsSession: 'live' });
    const first = await r.api(`/eudi/age/status/${start.json.requestId}`);
    assert.equal(first.json.status, 'failed');
    assert.equal(first.json.reason, 'no_age_claim_disclosed');
    assert.equal(internal.state.calls.length, 0, 'nothing was upgraded');

    const gets = eudiplo.state.sessionGets;
    const again = await r.api(`/eudi/age/status/${start.json.requestId}`);
    assert.equal(again.json.status, 'failed');
    assert.equal(again.json.reason, 'no_age_claim_disclosed');
    assert.equal(eudiplo.state.sessionGets, gets, 'a terminal failure is served from the transaction');
  } finally { await r.stop(); await internal.stop(); delete process.env.HHTTPS_INTERNAL_URL; }
});

test('AP4-34: /eudi/age/health discloses no backend URL and no doctype', async () => {
  resetStub();
  const r = await mountRouter(new Map());
  try {
    const h = await r.api('/eudi/age/health');
    assert.equal(h.status, 200);
    assert.deepEqual(Object.keys(h.json).sort(), ['module', 'ready', 'status']);
    assert.equal(h.json.ready, true);
    assert.equal(JSON.stringify(h.json).includes('127.0.0.1'), false, 'no internal URL is leaked');
    assert.equal(JSON.stringify(h.json).includes('eu.europa.ec'), false, 'no doctype is leaked');
  } finally { await r.stop(); }
});
