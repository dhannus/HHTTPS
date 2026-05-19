/**
 * Authenticated Privacy Pass batch issuance
 *
 * Flow:
 *   1. User authenticated themselves via the existing HHTTPS WebAuthn flow
 *      and got a sessionId.
 *   2. User declared a role (sessions row has role != null).
 *   3. Browser builds N TokenRequests locally (N blinded inputs).
 *   4. Browser POSTs { sessionId, role, requests: [<b64>, …] } to this endpoint.
 *   5. We validate the session, validate the role matches, check rate limit,
 *      run blind evaluation for each request, return the N TokenResponses.
 *
 * Rate limit: 10 tokens per credential_id per 24 hours by default. Enforced
 * via the pp_issuance_log table. This is the Sybil-resistance hinge: a single
 * authenticator can only mint a bounded number of anonymous tokens per day.
 */

import express from 'express';
import { getIssuer, ROLES, Ne, TOKEN_TYPE } from './keys.js';
import { issueTokenResponse }                from './issuer.js';
import { eligibilityFor }                    from './verifications.js';

// Defaults — tune via env or per-request later
const DEFAULT_BATCH_SIZE = 10;
const MAX_BATCH_SIZE     = 10;
const RATE_WINDOW_MS     = 24 * 60 * 60 * 1000;  // 24h
const RATE_MAX_TOKENS    = 10;

export const issuanceRouter = express.Router();
issuanceRouter.use(express.json({ limit: '32kb' }));

/**
 * POST /privacy-pass/issue
 *
 * Body: { sessionId: string, role: string, requests: string[] }
 *   - sessionId: from /hhttps/webauthn/auth/finish
 *   - role:      one of ROLES; must match session.role
 *   - requests:  array of base64-encoded TokenRequest blobs (52 bytes each)
 *
 * Response: { role, count, responses: string[] }  on success
 *           with each response a base64-encoded 145-byte TokenResponse
 */
issuanceRouter.post('/issue', async (req, res) => {
  try {
    const { sessionId, role, requests } = req.body || {};

    // ── Validate inputs ────────────────────────────────────────────────────
    if (typeof sessionId !== 'string' || !sessionId) {
      return res.status(400).json({ error: 'missing_session', detail: 'sessionId required' });
    }
    if (typeof role !== 'string' || !ROLES.includes(role)) {
      return res.status(400).json({
        error: 'invalid_role',
        detail: `role must be one of: ${ROLES.join(', ')}`,
      });
    }
    if (!Array.isArray(requests) || requests.length === 0) {
      return res.status(400).json({ error: 'no_requests', detail: 'requests array required' });
    }
    if (requests.length > MAX_BATCH_SIZE) {
      return res.status(400).json({
        error: 'batch_too_large',
        detail: `max ${MAX_BATCH_SIZE} requests per call`,
      });
    }

    // ── Lookup session in HHTTPS DB ────────────────────────────────────────
    const db = await import('../db.js');
    const session = await db.sessions.get(sessionId);

    if (!session) {
      return res.status(401).json({ error: 'invalid_session', detail: 'session not found or expired' });
    }
    if (!session.credentialId) {
      return res.status(401).json({ error: 'unauthenticated', detail: 'session has no credential' });
    }
    if (session.role !== role) {
      return res.status(403).json({
        error: 'role_mismatch',
        detail: `session role is ${session.role || 'unset'}, requested ${role}`,
      });
    }

    // ── Eligibility check: role-specific verification requirements ─────────
    const eligibility = await eligibilityFor(session.credentialId, role);
    if (!eligibility.ok) {
      return res.status(403).json({
        error: 'not_eligible',
        detail: eligibility.reason,
        missing: eligibility.missing,
        strict: eligibility.strict,
        completed: eligibility.completed,
        requirements: eligibility.requirements,
      });
    }

    // ── Rate limit check ───────────────────────────────────────────────────
    const usage = await getRecentIssuanceCount(session.credentialId, RATE_WINDOW_MS);
    const wanted = requests.length;
    if (usage + wanted > RATE_MAX_TOKENS) {
      const reset = Math.ceil(RATE_WINDOW_MS / 1000);
      res.setHeader('Retry-After', reset);
      return res.status(429).json({
        error: 'rate_limited',
        detail: `would exceed ${RATE_MAX_TOKENS} tokens per 24h (used ${usage}, wanted ${wanted})`,
        used_in_window: usage,
        max_per_window: RATE_MAX_TOKENS,
        window_seconds: reset,
      });
    }

    // ── Per-role issuer ────────────────────────────────────────────────────
    const issuer = getIssuer(role);

    // ── Process each TokenRequest ──────────────────────────────────────────
    const responses = [];
    for (let i = 0; i < requests.length; i++) {
      const reqBuf = Buffer.from(requests[i], 'base64');
      if (reqBuf.length !== 2 + 1 + Ne) {
        return res.status(400).json({
          error: 'malformed_request',
          detail: `request[${i}] length ${reqBuf.length} != expected ${2 + 1 + Ne}`,
        });
      }
      const tokenType = reqBuf.readUInt16BE(0);
      const truncKey  = reqBuf.readUInt8(2);
      if (tokenType !== TOKEN_TYPE) {
        return res.status(400).json({
          error: 'unsupported_token_type',
          detail: `request[${i}] type 0x${tokenType.toString(16)}`,
        });
      }
      if (truncKey !== issuer.tokenKeyId[issuer.tokenKeyId.length - 1]) {
        return res.status(400).json({
          error: 'key_id_mismatch',
          detail: `request[${i}] truncated_key_id does not match role=${role} issuer`,
        });
      }
      const blinded = reqBuf.subarray(3);
      const resp    = await issueTokenResponse(blinded, issuer);
      responses.push(resp.toString('base64'));
    }

    // ── Log issuance (rate limit accounting) ───────────────────────────────
    await logIssuance(session.credentialId, role, responses.length);

    res.json({
      role,
      count:      responses.length,
      responses,
      issued_at:  new Date().toISOString(),
      used_in_window: usage + responses.length,
      max_per_window: RATE_MAX_TOKENS,
    });

  } catch (err) {
    console.error('[PP issuance] error:', err);
    res.status(500).json({ error: 'issuance_failed', detail: err.message });
  }
});

// ─── Rate-limit DB helpers (via pool() from db.js) ───────────────────────────

async function getRecentIssuanceCount(credentialId, windowMs) {
  const db = await import('../db.js');
  const { rows } = await db.pool().query(
    `SELECT COALESCE(SUM(token_count), 0)::int AS n
       FROM pp_issuance_log
      WHERE credential_id = $1
        AND issued_at > NOW() - ($2 || ' milliseconds')::interval`,
    [credentialId, String(windowMs)]
  );
  return rows[0]?.n || 0;
}

async function logIssuance(credentialId, role, count) {
  const db = await import('../db.js');
  await db.pool().query(
    `INSERT INTO pp_issuance_log (credential_id, role, token_count, issued_at)
     VALUES ($1, $2, $3, NOW())`,
    [credentialId, role, count]
  );
}

/**
 * GET /privacy-pass/issuance/quota?sessionId=...
 *
 * Lets the wallet show "you have N tokens left for the next M hours".
 */
issuanceRouter.get('/issuance/quota', async (req, res) => {
  try {
    const sessionId = req.query.sessionId;
    if (!sessionId) return res.status(400).json({ error: 'missing_session' });

    const db = await import('../db.js');
    const session = await db.sessions.get(sessionId);
    if (!session) return res.status(401).json({ error: 'invalid_session' });

    const used = await getRecentIssuanceCount(session.credentialId, RATE_WINDOW_MS);
    res.json({
      used_in_window: used,
      max_per_window: RATE_MAX_TOKENS,
      remaining:      Math.max(0, RATE_MAX_TOKENS - used),
      window_seconds: Math.ceil(RATE_WINDOW_MS / 1000),
    });
  } catch (err) {
    res.status(500).json({ error: 'quota_failed', detail: err.message });
  }
});
