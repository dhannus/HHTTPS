// server/eudi-verifier/index.js
//
// HHTTPS — EUDI verification ORCHESTRATOR (in-process Express router).
//
// This module does NOT implement OpenID4VP/mdoc/trusted-list itself: EUDIPLO
// (OpenWallet Foundation, same host, :3002 — see backend-client.js) does all of
// that. This module is the bridge between EUDIPLO and HHTTPS. It runs INSIDE
// the HHTTPS server process (mounted in server.js), not as a separate service:
//
//   1. POST /eudi/<kind>/request    → create an EUDIPLO presentation offer;
//                                     return the openid4vp:// wallet link.
//   2. GET  /eudi/<kind>/status/:id → poll EUDIPLO; on a validated presentation,
//                                     sign the HMAC assertion (assertion.js) and
//                                     call the matching internal HHTTPS endpoint
//                                     to reissue the holder's token.
//
//   kind = age (age_over_NN via PID) | av (EU AV Profile attestation) | eid
//          (PID presentation → the `eudi` method).
//
// Same openid4vp:// URL is offered both as a QR (cross-device) and a deep-link
// (same-device) — the frontend decides which to show.
//
// Mount in server.js:  app.use('/eudi', createEudiVerifierRouter());

import express from 'express';
import crypto from 'crypto';
import rateLimit from 'express-rate-limit';
import {
  initTransaction,
  initAvTransaction,
  initEidTransaction,
  buildWalletLink,
  pollWalletResponse,
  extractVerifiedAgeClaims,
  forgetSession
} from './backend-client.js';
import { BackendError, mapBackendError } from './errors.js';
// AP4-47 (#228): the canonical assertion structures are shared with server.js.
import { signAssertion } from './assertion.js';

// NOTE: No QR library dependency on the backend. The module returns the
// openid4vp:// `deepLink`; the frontend renders it as a QR code (cross-device)
// or uses it directly as a tappable link (same-device). This keeps the server
// dependency-free — the same URL serves both surfaces.

// In-memory transaction store. Maps our requestId → transaction context.
// Sessions are short-lived (age verification completes in minutes); a Map with
// TTL cleanup is sufficient and avoids a DB schema change (consistent with the
// client-driven design — age_group lives in the token, not the DB).
//
// AP4-45 — OPERATING CONSTRAINT: this store is PROCESS-LOCAL. The HHTTPS server
// must run as a SINGLE Node instance (no cluster mode, no second replica behind
// a load balancer): a /eudi/*/status poll that lands on another instance than
// the /eudi/*/request that created the transaction answers 404 `expired`.
// Horizontal scaling needs this store in the database first.
const txStore = new Map();
const TX_TTL_MS = 10 * 60 * 1000; // 10 min
// AP4-37 (#214): hard upper bound on pending transactions (each one is an
// EUDIPLO session upstream). Expired entries are purged first; when the store
// is still full the request is refused (503) instead of growing without limit.
const MAX_TX = Number(process.env.EUDI_MAX_PENDING_TX) || 1000;

// AP4-39 (#222): bounded internal calls (age/upgrade, age/direct, eid/upgrade).
const INTERNAL_TIMEOUT_MS = Number(process.env.EUDI_INTERNAL_TIMEOUT_MS) || 8000;

// AP4-28 (#189): debug logging is a dev aid only (never in production) and
// never prints the wallet response body — only its top-level keys.
const DEBUG = process.env.EUDI_DEBUG === '1' && process.env.NODE_ENV !== 'production';
const debugKeys = (label, obj) => {
  if (DEBUG) console.log(`[EUDI-DEBUG] ${label} keys=${JSON.stringify(Object.keys(obj || {}))}`);
};

class TxStoreFull extends Error {
  constructor() { super('too many pending EUDI transactions'); this.name = 'TxStoreFull'; }
}

function purgeExpiredTx(now = Date.now()) {
  for (const [id, tx] of txStore) {
    if (now - tx.createdAt > TX_TTL_MS) txStore.delete(id);
  }
}
// Checked BEFORE the upstream call: a full store must not create an EUDIPLO
// session first and only then refuse (AP4-37).
function assertTxCapacity() {
  if (txStore.size >= MAX_TX) purgeExpiredTx();
  if (txStore.size >= MAX_TX) throw new TxStoreFull();
}
function putTx(requestId, ctx) {
  assertTxCapacity();
  txStore.set(requestId, { ...ctx, createdAt: Date.now() });
}
function getTx(requestId) {
  const tx = txStore.get(requestId);
  if (!tx) return null;
  if (Date.now() - tx.createdAt > TX_TTL_MS) { txStore.delete(requestId); return null; }
  return tx;
}
// Periodic cleanup of expired transactions.
setInterval(() => purgeExpiredTx(), 60_000).unref?.();

/** Test hook: number of stored transactions (AP4-37 regression test). */
export function _txStoreSize() { return txStore.size; }

// AP4-50 (#239): ONE place that reads the shared secret, ONE place that builds
// the internal URL, ONE place that POSTs — the three call* wrappers below only
// differ in the canonical payload (assertion.js) and the request body.
function verifierSecret() {
  const secret = process.env.EUDI_VERIFIER_SECRET;
  if (!secret) throw new Error('EUDI_VERIFIER_SECRET not configured');
  return secret;
}

const internalBase = () => process.env.HHTTPS_INTERNAL_URL || 'http://127.0.0.1:3000';

async function postInternal(endpoint, body) {
  const r = await fetch(`${internalBase()}/hhttps/${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(INTERNAL_TIMEOUT_MS)
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new BackendError(endpoint, r.status, data);
  return data;
}

/** A fresh single-use {nonce, iat} pair — the replay protection of AP4-27. */
const freshAssertionContext = () => ({ nonce: crypto.randomUUID(), iat: Date.now() });

// Call the internal /hhttps/age/upgrade endpoint with the verified age claims.
async function callAgeUpgrade(ageOver, hhttpsSessionId, currentToken) {
  const { nonce, iat } = freshAssertionContext();
  const payload = { sessionId: hhttpsSessionId, ageOver, nonce, iat };
  // → { hhttps:{token}, ageGroup:{...} }
  return postInternal('age/upgrade', {
    ...payload,
    currentToken: currentToken || null,
    assertion: signAssertion('age/upgrade', verifierSecret(), payload)
  });
}

// Call the internal /hhttps/age/direct endpoint — an AV Profile Proof of Age
// attestation WITHOUT an HHTTPS session. Since AK-28 the backend answers this
// with 403 email_verification_required unconditionally (no session-less
// bootstrap); the answer is passed through to the browser (#26). The canonical
// deliberately differs from the upgrade canonical (direct:true instead of a
// sessionId), so an assertion can never be replayed across the two endpoints.
async function callAgeDirect(ageOver) {
  const { nonce, iat } = freshAssertionContext();
  const payload = { ageOver, nonce, iat };
  return postInternal('age/direct', {
    ...payload,
    assertion: signAssertion('age/direct', verifierSecret(), payload)
  });
}

// Call the internal /hhttps/eid/upgrade endpoint after a valid PID presentation.
// Carries the holder's current token (if any) so orthogonal age claims survive
// the reissue. Zero-PII: no PID attribute is sent — the proof is the presentation.
async function callEidUpgrade(hhttpsSessionId, currentToken) {
  const { nonce, iat } = freshAssertionContext();
  const payload = { sessionId: hhttpsSessionId, nonce, iat };
  // → { hhttps:{token}, eudi:{...} }
  return postInternal('eid/upgrade', {
    ...payload,
    currentToken: currentToken || null,
    assertion: signAssertion('eid/upgrade', verifierSecret(), payload)
  });
}

/**
 * @param {object} [opts]
 * @param {Function} [opts.setIdentityCookie]  browser cookie setter (see below)
 * @param {Function} [opts.getSession]         sessionId → session|null (default db.sessions.get);
 *                                             injectable for unit tests (AP4-37)
 */
export function createEudiVerifierRouter({ setIdentityCookie, getSession } = {}) {
  const router = express.Router();
  router.use(express.json());

  // Browser-facing cookie setter. The /eudi/*/status handlers run on requests the
  // BROWSER makes directly, so this is where the upgraded token must be mirrored
  // into the httpOnly identity cookie. (The /hhttps/*/upgrade Set-Cookie reaches
  // only the internal server-to-server response and is discarded — that was the
  // bug where EUDI claims never reached the browser cookie.)
  const setCookie = (typeof setIdentityCookie === 'function') ? setIdentityCookie : () => {};
  // db.js is loaded lazily: the router is usable (and unit-testable) without a
  // database when the caller injects getSession.
  const lookupSession = (typeof getSession === 'function')
    ? getSession
    : async (id) => (await import('../db.js')).sessions.get(id);

  // AP4-37 (#214): the /*/request routes each create an EUDIPLO session upstream
  // — rate-limited per client on top of the global limiter.
  const requestLimit = rateLimit({
    max: Number(process.env.EUDI_REQUEST_RATE_MAX) || 20, windowMs: 60_000,
    standardHeaders: true, legacyHeaders: false,
    handler: (_req, res) => res.status(429).json({ error: 'Rate limit exceeded.', retryAfter: 60 })
  });

  // AP4-37: the HHTTPS session must exist (and be live) BEFORE anything is
  // created upstream. Returns the session or answers the request and returns null.
  async function requireSession(hhttpsSession, res) {
    if (!hhttpsSession || typeof hhttpsSession !== 'string') {
      res.status(400).json({ error: 'hhttpsSession is required.' });
      return null;
    }
    const session = await lookupSession(hhttpsSession);
    if (!session?.verified) {
      res.status(404).json({ error: 'session_not_found', detail: 'Unknown or expired HHTTPS session.' });
      return null;
    }
    return session;
  }

  function requestError(route, e, res) {
    if (e instanceof TxStoreFull) {
      console.warn(`[EUDI-VERIFIER] ${route}: transaction store full (${MAX_TX}) — refusing.`);
      return res.status(503).json({ error: 'too_many_pending_verifications', retryAfter: 60 });
    }
    console.error(`[EUDI-VERIFIER] ${route} error:`, e.message);
    res.status(502).json({ error: 'EU verifier backend unavailable.', detail: e.message });
  }

  // AP4-08 (#86): one poll per transaction at a time. The frontend polls every
  // 2.5 s and a second tab/poller must NOT trigger a second upgrade (two token
  // pairs, double stats/events): while a poll is in flight every concurrent
  // status request is answered `pending`; the terminal result (verified/failed)
  // is cached on the transaction and served from there afterwards.
  function cachedResult(tx, res, resultKey) {
    if (tx.status === 'verified') {
      if (tx.hhttps?.token) setCookie(res, tx.hhttps.token);  // browser cookie
      res.json({ status: 'verified', [resultKey]: tx[resultKey], hhttps: tx.hhttps });
      return true;
    }
    if (tx.status === 'failed') {
      res.json({ status: 'failed', reason: tx.reason || 'verification_failed' });
      return true;
    }
    if (tx.inflight) {
      res.json({ status: 'pending' });
      return true;
    }
    return false;
  }

  function markFailed(tx, reason) {
    tx.status = 'failed';
    tx.reason = reason;
    forgetSession(tx.transactionId);
  }

  // AP4-50 (#239): the three status routes were copies of each other — the only
  // real differences are the log/debug label, the result key and what is done
  // once the wallet has answered. `complete` returns { <resultKey>, hhttps } or
  // null when it has already answered the request itself (terminal failure).
  function statusHandler({ route, debugLabel, resultKey, complete }) {
    return async (req, res) => {
      const tx = getTx(req.params.requestId);
      if (!tx) return res.status(404).json({ status: 'expired' });
      // AP4-08/AP4-14: a terminal result (verified OR failed) is served from the
      // transaction — EUDIPLO is never polled again for it.
      if (cachedResult(tx, res, resultKey)) return;

      tx.inflight = true;
      try {
        const poll = await pollWalletResponse(tx.transactionId);
        if (poll.status === 'pending') return res.json({ status: 'pending' });
        if (poll.status === 'failed') {
          markFailed(tx, poll.reason);
          return res.json({ status: 'failed', reason: tx.reason });
        }
        debugKeys(debugLabel, poll.walletResponse);

        const result = await complete(tx, poll, res);
        if (!result) return;                       // `complete` already answered

        tx.status    = 'verified';
        tx[resultKey] = result[resultKey];
        tx.hhttps     = result.hhttps;

        if (tx.hhttps?.token) setCookie(res, tx.hhttps.token);  // ← mirror into browser cookie
        res.json({ status: 'verified', [resultKey]: result[resultKey], hhttps: result.hhttps });
      } catch (e) {
        console.error(`[EUDI-VERIFIER] ${route} error:`, e.message);
        const { httpStatus, body } = mapBackendError(e);   // 4xx of the backend pass through (#26)
        res.status(httpStatus).json(body);
      } finally {
        tx.inflight = false;
      }
    };
  }

  // Shared tail of the two AGE routes: read the validated booleans, refuse a
  // presentation that disclosed nothing, then bridge into HHTTPS.
  async function completeAge(tx, poll, res, bridge) {
    const ageOver = extractVerifiedAgeClaims(poll.walletResponse);
    if (!Object.values(ageOver).some(v => v === true)) {
      markFailed(tx, 'no_age_claim_disclosed');
      res.json({ status: 'failed', reason: tx.reason });
      return null;
    }
    const result = await bridge(ageOver, tx);
    return { ageGroup: result.ageGroup, hhttps: result.hhttps };
  }

  // Health: confirms the module is mounted and whether it is usable at all.
  // AP4-34: this route is UNAUTHENTICATED, so it must not disclose the internal
  // EUDIPLO URL, the requested doctypes or the wallet scheme — that is an
  // inventory of the deployment for anyone who asks. `ready` is the one bit a
  // monitor needs: the shared secret is present, so an upgrade can be signed.
  router.get('/age/health', (_req, res) => {
    res.json({
      module: 'eudi-verifier',
      status: 'ok',
      ready: !!process.env.EUDI_VERIFIER_SECRET
    });
  });

  // 1. Start an age verification. Body: { hhttpsSession, minAge? }
  //    minAge ∈ {14,16,18}; defaults to 18. Returns QR (data URL) + deep-link.
  router.post('/age/request', requestLimit, async (req, res) => {
    try {
      const { hhttpsSession, minAge, currentToken } = req.body || {};
      if (!await requireSession(hhttpsSession, res)) return;
      assertTxCapacity();                                   // AP4-37, before the upstream call
      const age = [14, 16, 18].includes(Number(minAge)) ? Number(minAge) : 18;

      const tx = await initTransaction(age);
      const walletLink = buildWalletLink(tx);
      const requestId = crypto.randomUUID();

      putTx(requestId, {
        transactionId: tx.transaction_id,
        nonce: tx.nonce,
        hhttpsSession,
        currentToken: currentToken || null,
        minAge: age,
        status: 'pending'
      });

      res.json({
        requestId,
        minAge: age,
        // Same URL, two surfaces: deep-link for same-device, QR for cross-device.
        // Frontend renders `deepLink` as a QR (e.g. via a small JS lib) for
        // cross-device, or uses it as a tappable link on the phone itself.
        deepLink: walletLink,
        expiresInMs: TX_TTL_MS,
        message: `Scan the QR code with your EUDI wallet, or open it directly on your phone.`
      });
    } catch (e) {
      requestError('/age/request', e, res);
    }
  });

  // 2. Poll status. Frontend hits this every ~2s until 'verified' or 'failed'.
  router.get('/age/status/:requestId', statusHandler({
    route: '/age/status', debugLabel: 'walletResponse', resultKey: 'ageGroup',
    // Bridge to HHTTPS: issue a verified token via /hhttps/age/upgrade.
    complete: (tx, poll, res) => completeAge(tx, poll, res,
      (ageOver) => callAgeUpgrade(ageOver, tx.hhttpsSession, tx.currentToken))
  }));

  // ─── AV Profile acceptance (e-mail-verified session required) ────────────────
  //
  // Accepts the EU AV Profile Proof of Age attestation (eu.europa.ec.av.1).
  // With a session (hhttpsSession supplied) the verified age lands on that
  // identity via /hhttps/age/upgrade, which requires a confirmed e-mail
  // (403 email_verification_required otherwise). WITHOUT a session there is no
  // bootstrap any more (AK-28): /hhttps/age/direct always answers 403
  // email_verification_required, and the status handler passes that through
  // to the browser as 403 { status:'error', error:'email_verification_required' }
  // (#26) so the page can point the user to the e-mail step.
  //
  // AP4-37: a request WITHOUT a session is answered with that same 403 right
  // away — the outcome is fixed (AK-28), so no EUDIPLO session is created for it.

  // 1. Start a direct AV verification. Body: { minAge?, hhttpsSession, currentToken? }
  router.post('/av/request', requestLimit, async (req, res) => {
    try {
      const { minAge, hhttpsSession, currentToken } = req.body || {};
      if (!hhttpsSession) {
        return res.status(403).json({
          status: 'error', error: 'email_verification_required',
          detail: 'Age proof requires a session with a verified email. Use /hhttps/age/upgrade.'
        });
      }
      if (!await requireSession(hhttpsSession, res)) return;
      assertTxCapacity();                                   // AP4-37, before the upstream call
      const age = [14, 16, 18].includes(Number(minAge)) ? Number(minAge) : 18;

      const tx = await initAvTransaction(age);
      // The EU AV app's intent filter binds the openid4vp scheme to host
      // `authorize` (verified in av-app-android-wallet-ui: openid4VpHost =
      // "authorize" in AndroidLibraryConventionPlugin.kt). EUDIPLO emits an
      // empty-host link, which Android then fails to resolve. Inserting the
      // host is semantically neutral in OID4VP (wallets read only the query
      // params); the replace targets exactly the empty-host form.
      const walletLink = buildWalletLink(tx)
        .replace(/^openid4vp:\/\/\?/, 'openid4vp://authorize?');
      const requestId = crypto.randomUUID();

      putTx(requestId, {
        transactionId: tx.transaction_id,
        nonce: tx.nonce,
        hhttpsSession: hhttpsSession || null,   // null ⇒ age/direct ⇒ 403 email gate (AK-28)
        currentToken: currentToken || null,
        minAge: age,
        kind: 'av',
        status: 'pending'
      });

      res.json({
        requestId,
        minAge: age,
        deepLink: walletLink,
        expiresInMs: TX_TTL_MS,
        message: 'Scan the QR code with your EU Age Verification app or EUDI wallet, or open it directly on your phone.'
      });
    } catch (e) {
      requestError('/av/request', e, res);
    }
  });

  // 2. Poll direct AV status.
  router.get('/av/status/:requestId', statusHandler({
    route: '/av/status', debugLabel: 'AV walletResponse', resultKey: 'ageGroup',
    // Session supplied → verified age lands on the EXISTING identity (upgrade
    // path). No session → age/direct, which always answers 403 (AK-28).
    complete: (tx, poll, res) => completeAge(tx, poll, res,
      (ageOver) => tx.hhttpsSession
        ? callAgeUpgrade(ageOver, tx.hhttpsSession, tx.currentToken)
        : callAgeDirect(ageOver))
  }));

  // ─── eID identity (orthogonal to age) ───────────────────────────────────────

  // 1. Start an eID identity verification. Body: { hhttpsSession, currentToken? }
  //    Returns a wallet deep-link (rendered as QR / tappable link by the frontend).
  router.post('/eid/request', requestLimit, async (req, res) => {
    try {
      const { hhttpsSession, currentToken } = req.body || {};
      if (!await requireSession(hhttpsSession, res)) return;
      assertTxCapacity();                                   // AP4-37, before the upstream call
      const tx = await initEidTransaction();
      const walletLink = buildWalletLink(tx);
      const requestId = crypto.randomUUID();

      putTx(requestId, {
        transactionId: tx.transaction_id,
        nonce: tx.nonce,
        hhttpsSession,
        currentToken: currentToken || null,
        kind: 'eid',
        status: 'pending'
      });

      res.json({
        requestId,
        deepLink: walletLink,
        expiresInMs: TX_TTL_MS,
        message: 'Scan the QR code with your EUDI wallet, or open it directly on your phone.'
      });
    } catch (e) {
      requestError('/eid/request', e, res);
    }
  });

  // 2. Poll eID status. A POSITIVE terminal EUDIPLO session = a valid PID
  //    presentation (AP4-24: negative/unknown states never count). ZERO-PII: we
  //    deliberately do NOT read any disclosed attribute; the validated
  //    presentation itself is the proof.
  router.get('/eid/status/:requestId', statusHandler({
    route: '/eid/status', debugLabel: 'eID walletResponse', resultKey: 'eudi',
    complete: async (tx) => {
      const upgrade = await callEidUpgrade(tx.hhttpsSession, tx.currentToken);
      return { eudi: upgrade.eudi, hhttps: upgrade.hhttps };
    }
  }));

  return router;
}
