/**
 * Privacy Pass Token Verifier — RFC 9577 §2.2 / RFC 9578 §6.2
 *
 * Thin Express handler that wraps the internal verifier.
 * For real cryptographic logic see ./verifier-internal.js.
 */

import { parseToken, parseTokenAndVerify } from './verifier-internal.js';

export async function handleVerify(req, res) {
  try {
    const b64 = req.body?.token;
    if (typeof b64 !== 'string') {
      throw new Error('Body must contain { "token": "<base64>" }');
    }

    const tokenBuf = Buffer.from(b64, 'base64');
    const token    = parseToken(tokenBuf);
    const valid    = await parseTokenAndVerify(tokenBuf);

    res.json({
      valid,
      ...(valid && {
        token_type: token.tokenType,
        nonce:      token.nonce.toString('base64url'),
      }),
      ...(!valid && { reason: 'authenticator mismatch' }),
    });

  } catch (err) {
    return res.status(400).json({
      valid: false,
      error: 'invalid_token',
      detail: err.message,
    });
  }
}
