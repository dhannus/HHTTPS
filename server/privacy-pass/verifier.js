/**
 * Privacy Pass Token Verifier — public endpoint.
 *
 * POST /privacy-pass/verify { token: <base64> }
 *   → { valid, role?, reason? }
 *
 * The `role` field tells the caller which issuer (and therefore which role
 * attestation) the token belongs to.
 */

import { parseToken, parseAndVerify, findIssuerForToken } from './verifier-internal.js';

export async function handleVerify(req, res) {
  try {
    const b64 = req.body?.token;
    if (typeof b64 !== 'string') {
      throw new Error('Body must contain { "token": "<base64>" }');
    }
    const buf    = Buffer.from(b64, 'base64');
    const result = await parseAndVerify(buf);
    const token  = parseToken(buf);

    res.json({
      valid: result.valid,
      ...(result.valid && {
        role:  result.issuer.role,
        nonce: token.nonce.toString('base64url'),
      }),
      ...(!result.valid && { reason: result.reason }),
    });

  } catch (err) {
    res.status(400).json({
      valid: false,
      error: 'invalid_token',
      detail: err.message,
    });
  }
}

/**
 * Privacy Pass Token Redeemer — consuming endpoint.
 *
 * POST /privacy-pass/redeem { token: <base64> }
 *   → { valid, redeemed, role?, reason? }
 *
 * Like /verify, but ALSO enforces one-time use: the token's nonce is recorded
 * in pp_redeemed. A second redemption of the same token is rejected as a
 * double-spend. Only the nonce is stored — no identity link, so the
 * redemption stays unlinkable.
 *
 * This is what a consuming surface (a "confirm" button) calls when a user
 * spends one of their anonymous tokens.
 */
export async function handleRedeem(req, res) {
  try {
    const b64 = req.body?.token;
    if (typeof b64 !== 'string') {
      throw new Error('Body must contain { "token": "<base64>" }');
    }
    const buf    = Buffer.from(b64, 'base64');
    const result = await parseAndVerify(buf);

    if (!result.valid) {
      return res.json({ valid: false, redeemed: false, reason: result.reason });
    }

    const token = parseToken(buf);
    const nonce = token.nonce.toString('base64url');
    const role  = result.issuer.role;

    // Atomic one-time-use check: INSERT fails on conflict if already spent.
    const db = await import('../db.js');
    const { rowCount } = await db.q(
      `INSERT INTO pp_redeemed (nonce, role) VALUES ($1, $2)
       ON CONFLICT (nonce) DO NOTHING`,
      [nonce, role]
    );

    if (rowCount === 0) {
      return res.json({
        valid: true, redeemed: false,
        reason: 'already_redeemed',
        role,
      });
    }

    res.json({ valid: true, redeemed: true, role, nonce });

  } catch (err) {
    res.status(400).json({
      valid: false, redeemed: false,
      error: 'invalid_token',
      detail: err.message,
    });
  }
}
