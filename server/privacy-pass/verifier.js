/**
 * Privacy Pass Token Verifier — RFC 9577 §2.2
 *
 * Verifies a Privacy Pass token presented in the Authorization header.
 * This is used when this issuer also acts as origin (for testing).
 * Real origins will typically run their own verification using the issuer's
 * public key fetched from the issuer directory.
 *
 * Token format per RFC 9577 §2.2:
 *
 *   struct {
 *     uint16 token_type;             // 0x0002
 *     uint8  nonce[32];
 *     uint8  challenge_digest[32];
 *     uint8  token_key_id[32];
 *     uint8  authenticator[Nk];      // Nk = 48 bytes (SHA-384 output)
 *   } Token;
 */

import {
  TOKEN_TYPE,
  getPrivateKey,
  getTokenKeyId,
} from './keys.js';

const TOKEN_SIZE_P384 = 2 + 32 + 32 + 32 + 48;  // 146 bytes total

/**
 * Parse a Token from a raw byte buffer.
 */
function parseToken(buf) {
  if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf);

  if (buf.length !== TOKEN_SIZE_P384) {
    throw new Error(`Token length ${buf.length} != expected ${TOKEN_SIZE_P384}`);
  }

  return {
    tokenType:       buf.readUInt16BE(0),
    nonce:           buf.subarray(2,   34),
    challengeDigest: buf.subarray(34,  66),
    tokenKeyId:      buf.subarray(66,  98),
    authenticator:   buf.subarray(98, 146),
  };
}

/**
 * POST /privacy-pass/verify
 *
 * Accepts a base64-encoded token in the JSON body and verifies it.
 * For development and testing only — production origins verify locally
 * using the issuer's public key.
 */
export async function handleVerify(req, res) {
  try {
    const b64 = req.body?.token;
    if (typeof b64 !== 'string') {
      throw new Error('Body must contain { "token": "<base64>" }');
    }

    const tokenBuf = Buffer.from(b64, 'base64');
    const token    = parseToken(tokenBuf);

    if (token.tokenType !== TOKEN_TYPE) {
      throw new Error(`Unsupported token_type 0x${token.tokenType.toString(16)}`);
    }
    if (!token.tokenKeyId.equals(getTokenKeyId())) {
      throw new Error('token_key_id does not match current issuer key');
    }

    // ── VOPRF token verification ──────────────────────────────────────────
    //
    // TODO: implement once @cloudflare/voprf-ts is installed.
    //
    // For Token Type 0x0002 (privately verifiable), the authenticator is
    // verified by recomputing OPRF.Evaluate(privateKey, token_input) and
    // comparing in constant time:
    //
    //   import { Oprf, OPRFServer } from '@cloudflare/voprf-ts';
    //   const suite  = Oprf.Suite.P384_SHA384;
    //   const server = new OPRFServer(suite, getPrivateKey());
    //   const tokenInput = Buffer.concat([
    //     Buffer.from([0x00, 0x02]),    // token_type
    //     token.nonce,
    //     token.challengeDigest,
    //     token.tokenKeyId,
    //   ]);
    //   const expected = await server.evaluate(tokenInput);
    //   const valid    = timingSafeEqual(expected, token.authenticator);

    void getPrivateKey();
    void token;

    return res.status(501).json({
      error: 'not_implemented',
      detail: 'VOPRF authenticator verification pending. See server/privacy-pass/verifier.js',
    });

  } catch (err) {
    return res.status(400).json({
      error: 'invalid_token',
      detail: err.message,
    });
  }
}
