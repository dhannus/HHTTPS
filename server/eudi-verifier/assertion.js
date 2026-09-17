// server/eudi-verifier/assertion.js
//
// AP4-47 (#228): the ONE place that defines the HMAC-SHA256 assertions the
// eudi-verifier signs and the internal HHTTPS endpoints
// (/hhttps/age/upgrade, /hhttps/age/direct, /hhttps/eid/upgrade) re-compute.
//
// Before, the canonical structure, the HMAC and the constant-time compare were
// copied three times on each side — signer and verifier could drift apart
// silently, and a drift means "every upgrade is rejected" (or, worse, that a
// field stops being covered by the signature).
//
// The canonical structure DIFFERS PER ENDPOINT ON PURPOSE, so an assertion can
// never be replayed across them:
//
//   age/upgrade  { sessionId, ageOver:{14,16,18}, nonce, iat }
//   age/direct   { direct:true, ageOver:{14,16,18}, nonce, iat }   ← no sessionId
//   eid/upgrade  { sessionId, eidVerified:true, nonce, iat }
//
// JSON.stringify of an object literal preserves insertion order, so the key
// order below IS part of the wire format: do not reorder, rename or add fields
// without changing signer and verifier in the same commit (they now share this
// file, so that is one edit).

import crypto from 'crypto';

/** Freshness window of an assertion (iat must not be older than this). */
export const ASSERTION_MAX_AGE_MS = 300_000;   // 5 min
/** Tolerated clock skew of a verifier that runs slightly ahead. */
export const ASSERTION_CLOCK_SKEW_MS = 60_000; // 1 min

/** The three disclosed age booleans, normalised to strict booleans. */
const ageOverTriplet = (ageOver) => ({
  age_over_14: ageOver?.age_over_14 === true,
  age_over_16: ageOver?.age_over_16 === true,
  age_over_18: ageOver?.age_over_18 === true
});

const CANONICAL = {
  'age/upgrade': ({ sessionId, ageOver, nonce, iat }) => JSON.stringify({
    sessionId,
    ageOver: ageOverTriplet(ageOver),
    nonce: nonce || null,
    iat:   iat   || null
  }),
  'age/direct': ({ ageOver, nonce, iat }) => JSON.stringify({
    direct: true,
    ageOver: ageOverTriplet(ageOver),
    nonce: nonce || null,
    iat:   iat   || null
  }),
  'eid/upgrade': ({ sessionId, nonce, iat }) => JSON.stringify({
    sessionId,
    eidVerified: true,
    nonce: nonce || null,
    iat:   iat   || null
  })
};

/** The endpoint names that have an assertion contract. */
export const ASSERTION_KINDS = Object.keys(CANONICAL);

/** The exact string both sides HMAC. Exported for tests. */
export function canonicalAssertion(kind, payload) {
  const build = CANONICAL[kind];
  if (!build) throw new Error(`unknown assertion kind: ${kind}`);
  return build(payload || {});
}

/** Sign the canonical payload of `kind` → hex HMAC-SHA256. */
export function signAssertion(kind, secret, payload) {
  return crypto.createHmac('sha256', secret).update(canonicalAssertion(kind, payload)).digest('hex');
}

/**
 * Constant-time check of a received assertion against the canonical payload.
 * Compares the LENGTH first — timingSafeEqual throws on differing lengths.
 * @returns {boolean} true when the assertion is authentic.
 */
export function verifyAssertion(kind, secret, payload, assertion) {
  const a = Buffer.from(String(assertion), 'utf8');
  const b = Buffer.from(signAssertion(kind, secret, payload), 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
