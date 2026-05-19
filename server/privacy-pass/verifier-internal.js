/**
 * Internal helper: parse a raw Privacy Pass token (146 bytes), find the issuer
 * that minted it via its token_key_id, and run VOPRF.Evaluate + constant-time
 * compare to verify the authenticator.
 *
 * Returns { valid, issuer } on syntactic success (where issuer may be null if
 * the token_key_id matches no known issuer). Throws on malformed input.
 */

import { timingSafeEqual } from 'crypto';
import { VOPRFServer }     from '@cloudflare/voprf-ts';

import { TOKEN_TYPE, SUITE, Ns, listIssuers, getIssuer } from './keys.js';

const TOKEN_SIZE = 2 + 32 + 32 + 32 + Ns;  // 146 bytes

// One VOPRFServer per role
const _servers = new Map();
function srv(issuer) {
  let s = _servers.get(issuer.role);
  if (!s) { s = new VOPRFServer(SUITE, issuer.privateKey); _servers.set(issuer.role, s); }
  return s;
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
 * Find which issuer (by role) a token was issued by.
 * Returns the issuer descriptor or null if no match.
 */
export function findIssuerForToken(token) {
  for (const role of listIssuers()) {
    const i = getIssuer(role);
    if (i.tokenKeyId.equals(token.tokenKeyId)) return i;
  }
  return null;
}

export async function parseAndVerify(buf) {
  const token = parseToken(buf);

  if (token.tokenType !== TOKEN_TYPE) {
    throw new Error(`Unsupported token_type 0x${token.tokenType.toString(16)}`);
  }
  const issuer = findIssuerForToken(token);
  if (!issuer) {
    return { valid: false, issuer: null, reason: 'token_key_id matches no known issuer' };
  }

  const tokenInput = token.raw.subarray(0, 2 + 32 + 32 + 32);
  const expected   = await srv(issuer).evaluate(tokenInput);

  if (expected.length !== token.authenticator.length) {
    return { valid: false, issuer, reason: 'authenticator length mismatch' };
  }
  const ok = timingSafeEqual(Buffer.from(expected), Buffer.from(token.authenticator));
  return { valid: ok, issuer, reason: ok ? null : 'authenticator mismatch' };
}
