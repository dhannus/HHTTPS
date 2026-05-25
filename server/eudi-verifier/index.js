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
import {
  initTransaction,
  buildWalletLink,
  pollWalletResponse,
  extractAgeClaims,
  config as backendConfig
} from './backend-client.js';

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

function putTx(requestId, ctx) {
  txStore.set(requestId, { ...ctx, createdAt: Date.now() });
}
function getTx(requestId) {
  const tx = txStore.get(requestId);
  if (!tx) return null;
  if (Date.now() - tx.createdAt > TX_TTL_MS) { txStore.delete(requestId); return null; }
  return tx;
}
// Periodic cleanup of expired transactions.
setInterval(() => {
  const now = Date.now();
  for (const [id, tx] of txStore) {
    if (now - tx.createdAt > TX_TTL_MS) txStore.delete(id);
  }
}, 60_000).unref?.();

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

// Call the internal /hhttps/age/upgrade endpoint with the verified age claims.
async function callAgeUpgrade(ageOver, hhttpsSessionId) {
  const secret = process.env.EUDI_VERIFIER_SECRET;
  if (!secret) throw new Error('EUDI_VERIFIER_SECRET not configured');

  const nonce = crypto.randomUUID();
  const iat = Date.now();
  const assertion = buildUpgradeAssertion(secret, {
    sessionId: hhttpsSessionId, ageOver, nonce, iat
  });

  const upgradeUrl =
    (process.env.HHTTPS_INTERNAL_URL || 'http://127.0.0.1:3000') + '/hhttps/age/upgrade';

  const r = await fetch(upgradeUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sessionId: hhttpsSessionId, ageOver, assertion, nonce, iat })
  });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`age/upgrade failed (${r.status}): ${body.error || ''}`);
  return body; // { hhttps:{token}, ageGroup:{...} }
}

export function createEudiVerifierRouter() {
  const router = express.Router();
  router.use(express.json());

  // Health: confirms the module is mounted and shows backend config (no secrets).
  router.get('/age/health', (_req, res) => {
    res.json({
      module: 'eudi-verifier',
      status: 'ok',
      backend: backendConfig.BACKEND,
      doctype: backendConfig.AV_DOCTYPE,
      scheme: backendConfig.AUTH_SCHEME,
      secretConfigured: !!process.env.EUDI_VERIFIER_SECRET
    });
  });

  // 1. Start an age verification. Body: { hhttpsSession, minAge? }
  //    minAge ∈ {14,16,18}; defaults to 18. Returns QR (data URL) + deep-link.
  router.post('/age/request', async (req, res) => {
    try {
      const { hhttpsSession, minAge } = req.body || {};
      if (!hhttpsSession) {
        return res.status(400).json({ error: 'hhttpsSession is required.' });
      }
      const age = [14, 16, 18].includes(Number(minAge)) ? Number(minAge) : 18;

      const tx = await initTransaction(age);
      const walletLink = buildWalletLink(tx);
      const requestId = crypto.randomUUID();

      putTx(requestId, {
        transactionId: tx.transaction_id,
        nonce: tx.nonce,
        hhttpsSession,
        minAge: age,
        status: 'pending'
      });

      const qrDataUrl = null; // QR is rendered client-side from deepLink (no backend dep)

      res.json({
        requestId,
        minAge: age,
        // Same URL, two surfaces: deep-link for same-device, QR for cross-device.
        // Frontend renders `deepLink` as a QR (e.g. via a small JS lib) for
        // cross-device, or uses it as a tappable link on the phone itself.
        deepLink: walletLink,
        expiresInMs: TX_TTL_MS,
        message: `Scanne den QR-Code mit deiner EUDI-Wallet, oder öffne ihn auf dem Handy direkt.`
      });
    } catch (e) {
      console.error('[EUDI-VERIFIER] /age/request error:', e.message);
      res.status(502).json({ error: 'EU verifier backend unavailable.', detail: e.message });
    }
  });

  // 2. Poll status. Frontend hits this every ~2s until 'verified' or 'failed'.
  router.get('/age/status/:requestId', async (req, res) => {
    try {
      const tx = getTx(req.params.requestId);
      if (!tx) return res.status(404).json({ status: 'expired' });

      // Already completed in a previous poll — return the cached result.
      if (tx.status === 'verified') {
        return res.json({ status: 'verified', ageGroup: tx.ageGroup, hhttps: tx.hhttps });
      }

      const poll = await pollWalletResponse(tx.transactionId, req.query.response_code);
      if (poll.status === 'pending') {
        return res.json({ status: 'pending' });
      }

      // Wallet responded — extract validated age booleans.
      const ageOver = extractAgeClaims(poll.walletResponse);
      const proven = Object.values(ageOver).some(v => v === true);
      if (!proven) {
        tx.status = 'failed';
        return res.json({ status: 'failed', reason: 'no_age_claim_disclosed' });
      }

      // Bridge to HHTTPS: issue a verified token via /hhttps/age/upgrade.
      const upgrade = await callAgeUpgrade(ageOver, tx.hhttpsSession);
      tx.status = 'verified';
      tx.ageGroup = upgrade.ageGroup;
      tx.hhttps = upgrade.hhttps;

      res.json({ status: 'verified', ageGroup: upgrade.ageGroup, hhttps: upgrade.hhttps });
    } catch (e) {
      console.error('[EUDI-VERIFIER] /age/status error:', e.message);
      res.status(502).json({ status: 'error', detail: e.message });
    }
  });

  return router;
}
