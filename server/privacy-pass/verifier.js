/**
 * Privacy Pass Token Verifier — RFC 9577 §2.2 / RFC 9578 §6.2
 *
 * Verifies a Privacy Pass token presented in the Authorization header.
 * This endpoint is for development and testing — production origins typically
 * verify tokens locally by running the same code with the issuer's public key.
 *
 * Token format per RFC 9577 §2.2 (for Token Type 0x0002):
 *
 *   struct {
 *     uint16 token_type;             // 0x0002
 *     uint8  nonce[32];
 *     uint8  challenge_digest[32];
 *     uint8  token_key_id[32];
 *     uint8  authenticator[Nk];      // Nk = 48 bytes (SHA-384 output)
 *   } Token;
 *
 * Verification algorithm per RFC 9578 §6.2:
 *
 *   1. Reconstruct token_input = token_type || nonce || challenge_digest || token_key_id
 *   2. expected_auth = VOPRF.Evaluate(skS, token_input)
 *   3. Token is valid iff constant_time_compare(expected_auth, authenticator) == true
 *      and token_type / token_key_id match the issuer's current key.
 */

import { timingSafeEqual } from 'crypto';
import { VOPRFServer }     from '@cloudflare/voprf-ts';

import {
  TOKEN_TYPE,
  SUITE,
  Ns,
  getPrivateKey,
  getTokenKeyId,
} from './keys.js';

const TOKEN_SIZE = 2 + 32 + 32 + 32 + Ns;  // 146 bytes total

let _server = null;
function getServer() {
  if (!_server) _server = new VOPRFServer(SUITE, getPrivateKey());
  return _server;
}

function parseToken(buf) {
  if (!Buffer.isBuffer(buf)) buf = Buffer.from(buf);
  if (buf.length !== TOKEN_SIZE) {
    throw new Error(`Token length ${buf.length} != expected ${TOKEN_SIZE}`);
  }
  return {
    raw:             buf,
    tokenType:       buf.readUInt16BE(0),
    nonce:           buf.subarray(2,   34),
    challengeDigest: buf.subarray(34,  66),
    tokenKeyId:      buf.subarray(66,  98),
    authenticator:   buf.subarray(98, 146),
  };
}

/**
 * Run the cryptographic verification for a parsed Token.
 * Returns true iff the token is valid and was issued by this server.
 */
export async function verifyTokenStructure(token) {
  if (token.tokenType !== TOKEN_TYPE) {
    throw new Error(`Unsupported token_type 0x${token.tokenType.toString(16)}`);
  }
  if (!token.tokenKeyId.equals(getTokenKeyId())) {
    throw new Error('token_key_id does not match current issuer key');
  }

  // token_input is the first 98 bytes of the Token (everything except authenticator)
  const tokenInput = token.raw.subarray(0, 2 + 32 + 32 + 32);

  // VOPRF.Evaluate(skS, token_input) — for privately verifiable tokens, the
  // server holding the private key can recompute the authenticator and check it.
  const expected = await getServer().evaluate(tokenInput);

  if (expected.length !== token.authenticator.length) {
    return false;
  }

  // Constant-time comparison
  return timingSafeEqual(Buffer.from(expected), Buffer.from(token.authenticator));
}

/**
 * POST /privacy-pass/verify
 *
 * Accepts a base64-encoded token in the JSON body and verifies it.
 * Returns { valid: true } or { valid: false, reason: "..." }.
 */
export async function handleVerify(req, res) {
  try {
    const b64 = req.body?.token;
    if (typeof b64 !== 'string') {
      throw new Error('Body must contain { "token": "<base64>" }');
    }

    const tokenBuf = Buffer.from(b64, 'base64');
    const token    = parseToken(tokenBuf);

    const valid = await verifyTokenStructure(token);

    if (valid) {
      res.json({
        valid: true,
        token_type: token.tokenType,
        nonce:      token.nonce.toString('base64url'),
      });
    } else {
      res.json({
        valid: false,
        reason: 'authenticator mismatch',
      });
    }

  } catch (err) {
    return res.status(400).json({
      valid: false,
      error: 'invalid_token',
      detail: err.message,
    });
  }
}
