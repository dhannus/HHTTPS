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
