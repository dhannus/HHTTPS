// server/eudi-verifier/index.js
//
// HHTTPS Phase 3 — EUDI age-verification ORCHESTRATOR (Node module).
//
// This module does NOT implement OpenID4VP/mdoc/ZKP/trusted-list itself — the
// official EU Verifier Endpoint backend (Docker, :8080) does all of that. This
// module is the bridge between that backend and HHTTPS:
//
//   1. POST /eudi/age/request      → init a transaction on the EU backend with an
//                                     age_over_NN DCQL query; return QR + deep-link.
//   2. GET  /eudi/age/status/:id   → poll the EU backend; on success, read the
//                                     validated age_over_NN, build the HMAC
//                                     assertion, and call /hhttps/age/upgrade
//                                     (Phase 3 step 2) to issue a verified token.
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
  forgetSession,
  config as backendConfig
} from './backend-client.js';
import { BackendError, mapBackendError } from './errors.js';

// NOTE: No QR library dependency on the backend. The module returns the
// openid4vp:// `deepLink`; the frontend renders it as a QR code (cross-device)
// or uses it directly as a tappable link (same-device). This keeps the server
// dependency-free — the same URL serves both surfaces.

// In-memory transaction store. Maps our requestId → transaction context.
// Sessions are short-lived (age verification completes in minutes); a Map with
// TTL cleanup is sufficient and avoids a DB schema change (consistent with the
// client-driven design — age_group lives in the token, not the DB).
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

// Build the HMAC-SHA256 assertion that /hhttps/age/upgrade (step 2) expects.
// MUST match the canonical structure the upgrade endpoint recomputes exactly.
function buildUpgradeAssertion(secret, { sessionId, ageOver, nonce, iat }) {
  const canonical = JSON.stringify({
    sessionId,
    ageOver: {
      age_over_14: ageOver.age_over_14 === true,
      age_over_16: ageOver.age_over_16 === true,
      age_over_18: ageOver.age_over_18 === true
    },
    nonce: nonce || null,
    iat: iat || null
  });
  return crypto.createHmac('sha256', secret).update(canonical).digest('hex');
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

// Call the internal /hhttps/age/upgrade endpoint with the verified age claims.
async function callAgeUpgrade(ageOver, hhttpsSessionId, currentToken) {
  const secret = process.env.EUDI_VERIFIER_SECRET;
  if (!secret) throw new Error('EUDI_VERIFIER_SECRET not configured');

  const nonce = crypto.randomUUID();
  const iat = Date.now();
  const assertion = buildUpgradeAssertion(secret, {
    sessionId: hhttpsSessionId, ageOver, nonce, iat
  });
  // → { hhttps:{token}, ageGroup:{...} }
  return postInternal('age/upgrade', {
    sessionId: hhttpsSessionId, ageOver, assertion, nonce, iat, currentToken: currentToken || null
  });
}

// Call the internal /hhttps/age/direct endpoint — an AV Profile Proof of Age
// attestation WITHOUT an HHTTPS session. Since AK-28 the backend answers this
// with 403 email_verification_required unconditionally (no session-less
// bootstrap); the answer is passed through to the browser (#26). The canonical
// deliberately differs from the upgrade canonical (direct:true instead of a
// sessionId), so an assertion can never be replayed across the two endpoints.
async function callAgeDirect(ageOver) {
  const secret = process.env.EUDI_VERIFIER_SECRET;
  if (!secret) throw new Error('EUDI_VERIFIER_SECRET not configured');

  const nonce = crypto.randomUUID();
  const iat = Date.now();
  const canonical = JSON.stringify({
    direct: true,
    ageOver: {
      age_over_14: ageOver.age_over_14 === true,
      age_over_16: ageOver.age_over_16 === true,
      age_over_18: ageOver.age_over_18 === true
    },
    nonce, iat
  });
  const assertion = crypto.createHmac('sha256', secret).update(canonical).digest('hex');
  // → { hhttps:{token, refreshToken, sessionId, userId}, ageGroup:{...} }
  return postInternal('age/direct', { ageOver, assertion, nonce, iat });
}

// Call the internal /hhttps/eid/upgrade endpoint after a valid PID presentation.
// Carries the holder's current token (if any) so orthogonal age claims survive
// the reissue. Zero-PII: no PID attribute is sent — the proof is the presentation.
async function callEidUpgrade(hhttpsSessionId, currentToken) {
  const secret = process.env.EUDI_VERIFIER_SECRET;
  if (!secret) throw new Error('EUDI_VERIFIER_SECRET not configured');

  const nonce = crypto.randomUUID();
  const iat = Date.now();
  const canonical = JSON.stringify({ sessionId: hhttpsSessionId, eidVerified: true, nonce, iat });
  const assertion = crypto.createHmac('sha256', secret).update(canonical).digest('hex');
  // → { hhttps:{token}, eudi:{...} }
  return postInternal('eid/upgrade', {
    sessionId: hhttpsSessionId, currentToken: currentToken || null, nonce, iat, assertion
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

  // Health: confirms the module is mounted and shows backend config (no secrets).
  router.get('/age/health', (_req, res) => {
    res.json({
      module: 'eudi-verifier',
      status: 'ok',
      backend: backendConfig.BACKEND,
      doctype: backendConfig.AV_DOCTYPE,
      avProfileDoctype: backendConfig.AV_PROFILE_DOCTYPE,
      scheme: backendConfig.AUTH_SCHEME,
      secretConfigured: !!process.env.EUDI_VERIFIER_SECRET
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
  router.get('/age/status/:requestId', async (req, res) => {
    const tx = getTx(req.params.requestId);
    if (!tx) return res.status(404).json({ status: 'expired' });
    if (cachedResult(tx, res, 'ageGroup')) return;

    tx.inflight = true;
    try {
      const poll = await pollWalletResponse(tx.transactionId, req.query.response_code);
      if (poll.status === 'pending') {
        return res.json({ status: 'pending' });
      }
      if (poll.status === 'failed') {
        markFailed(tx, poll.reason);
        return res.json({ status: 'failed', reason: tx.reason });
      }

      // Wallet responded — extract validated age booleans.
      const ageOver = extractVerifiedAgeClaims(poll.walletResponse);
      debugKeys('walletResponse', poll.walletResponse);
      const proven = Object.values(ageOver).some(v => v === true);
      if (!proven) {
        markFailed(tx, 'no_age_claim_disclosed');
        return res.json({ status: 'failed', reason: tx.reason });
      }

      // Bridge to HHTTPS: issue a verified token via /hhttps/age/upgrade.
      const upgrade = await callAgeUpgrade(ageOver, tx.hhttpsSession, tx.currentToken);
      tx.status = 'verified';
      tx.ageGroup = upgrade.ageGroup;
      tx.hhttps = upgrade.hhttps;

      if (tx.hhttps?.token) setCookie(res, tx.hhttps.token);  // ← mirror into browser cookie
      res.json({ status: 'verified', ageGroup: upgrade.ageGroup, hhttps: upgrade.hhttps });
    } catch (e) {
      console.error('[EUDI-VERIFIER] /age/status error:', e.message);
      const { httpStatus, body } = mapBackendError(e);   // 4xx of the backend pass through (#26)
      res.status(httpStatus).json(body);
    } finally {
      tx.inflight = false;
    }
  });

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
  router.get('/av/status/:requestId', async (req, res) => {
    const tx = getTx(req.params.requestId);
    if (!tx) return res.status(404).json({ status: 'expired' });
    if (cachedResult(tx, res, 'ageGroup')) return;

    tx.inflight = true;
    try {
      const poll = await pollWalletResponse(tx.transactionId, req.query.response_code);
      if (poll.status === 'pending') {
        return res.json({ status: 'pending' });
      }
      if (poll.status === 'failed') {
        markFailed(tx, poll.reason);
        return res.json({ status: 'failed', reason: tx.reason });
      }

      const ageOver = extractVerifiedAgeClaims(poll.walletResponse);
      debugKeys('AV walletResponse', poll.walletResponse);
      const proven = Object.values(ageOver).some(v => v === true);
      if (!proven) {
        markFailed(tx, 'no_age_claim_disclosed');
        return res.json({ status: 'failed', reason: tx.reason });
      }

      // Session supplied → verified age lands on the EXISTING identity (upgrade
      // path). No session → age/direct, which always answers 403 (AK-28).
      const result = tx.hhttpsSession
        ? await callAgeUpgrade(ageOver, tx.hhttpsSession, tx.currentToken)
        : await callAgeDirect(ageOver);

      tx.status = 'verified';
      tx.ageGroup = result.ageGroup;
      tx.hhttps = result.hhttps;

      if (tx.hhttps?.token) setCookie(res, tx.hhttps.token);  // ← mirror into browser cookie
      res.json({ status: 'verified', ageGroup: result.ageGroup, hhttps: result.hhttps });
    } catch (e) {
      console.error('[EUDI-VERIFIER] /av/status error:', e.message);
      const { httpStatus, body } = mapBackendError(e);   // 4xx of the backend pass through (#26)
      res.status(httpStatus).json(body);
    } finally {
      tx.inflight = false;
    }
  });

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
  //    presentation (AP4-24: negative/unknown states never count).
  router.get('/eid/status/:requestId', async (req, res) => {
    const tx = getTx(req.params.requestId);
    if (!tx) return res.status(404).json({ status: 'expired' });
    if (cachedResult(tx, res, 'eudi')) return;

    tx.inflight = true;
    try {
      const poll = await pollWalletResponse(tx.transactionId, req.query.response_code);
      if (poll.status === 'pending') {
        return res.json({ status: 'pending' });
      }
      if (poll.status === 'failed') {
        markFailed(tx, poll.reason);
        return res.json({ status: 'failed', reason: tx.reason });
      }
      debugKeys('eID walletResponse', poll.walletResponse);

      // Terminal session → valid PID presentation. ZERO-PII: we deliberately do
      // NOT read any disclosed attribute; the validated presentation is the proof.
      const upgrade = await callEidUpgrade(tx.hhttpsSession, tx.currentToken);
      tx.status = 'verified';
      tx.eudi = upgrade.eudi;
      tx.hhttps = upgrade.hhttps;

      if (tx.hhttps?.token) setCookie(res, tx.hhttps.token);  // ← mirror into browser cookie
      res.json({ status: 'verified', eudi: upgrade.eudi, hhttps: upgrade.hhttps });
    } catch (e) {
      console.error('[EUDI-VERIFIER] /eid/status error:', e.message);
      const { httpStatus, body } = mapBackendError(e);   // 4xx of the backend pass through (#26)
      res.status(httpStatus).json(body);
    } finally {
      tx.inflight = false;
    }
  });

  return router;
}
