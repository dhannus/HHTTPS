/**
 * Internal helper: parse a raw Privacy Pass token (146 bytes) and verify it.
 *
 * Used by both verifier.js (public /privacy-pass/verify endpoint) and demo.js
 * (combined PP + HHTTPS protected endpoint).
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

const TOKEN_SIZE = 2 + 32 + 32 + 32 + Ns;  // 146 bytes

let _server = null;
function getServer() {
  if (!_server) _server = new VOPRFServer(SUITE, getPrivateKey());
  return _server;
}

export function parseToken(buf) {
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
 * Full verification pipeline: parse, sanity-check, then VOPRF.Evaluate +
 * constant-time compare. Returns true iff the token is valid for this issuer.
 */
export async function parseTokenAndVerify(buf) {
  const token = parseToken(buf);

  if (token.tokenType !== TOKEN_TYPE) {
    throw new Error(`Unsupported token_type 0x${token.tokenType.toString(16)}`);
  }
  if (!token.tokenKeyId.equals(getTokenKeyId())) {
    throw new Error('token_key_id does not match current issuer key');
  }

  const tokenInput = token.raw.subarray(0, 2 + 32 + 32 + 32);
  const expected   = await getServer().evaluate(tokenInput);

  if (expected.length !== token.authenticator.length) return false;
  return timingSafeEqual(Buffer.from(expected), Buffer.from(token.authenticator));
}
