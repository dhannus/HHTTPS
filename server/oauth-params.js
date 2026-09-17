// Pure input validation for the OAuth authorization request parameters that
// end up on authorization_codes (#31). Used by GET /hhttps/oauth/authorize
// (error → redirect) and POST /hhttps/oauth/approve (error → JSON 400).
//
// - state / nonce: opaque client values, echoed back / put in the id_token.
//   The columns are TEXT since migration-phase-3a1; the limit below only
//   keeps URLs and rows bounded.
// - code_challenge: RFC 7636 §4.2 — 43..128 chars of the unreserved set
//   [A-Za-z0-9._~-] (base64url of a SHA-256 is exactly 43 chars).
// - code_challenge_method: 'S256' | 'plain' (default 'plain' when absent,
//   as the token endpoint has always assumed).

export const STATE_MAX_LENGTH          = 2048;
export const NONCE_MAX_LENGTH          = 2048;
export const CODE_CHALLENGE_MIN_LENGTH = 43;
export const CODE_CHALLENGE_MAX_LENGTH = 128;
export const CODE_CHALLENGE_METHODS    = Object.freeze(['S256', 'plain']);
export const SCOPE_MAX_LENGTH          = 1024;

const CODE_CHALLENGE_RE = /^[A-Za-z0-9._~-]+$/;

const fail = (description) => ({ ok: false, error: 'invalid_request', description });

function checkOpaque(name, value, max) {
  if (value === undefined || value === null || value === '') return null;
  if (typeof value !== 'string') return fail(`${name} must be a single string value.`);
  if (value.length > max) return fail(`${name} must not exceed ${max} characters.`);
  return null;
}

/**
 * @returns {{ok:true} | {ok:false, error:'invalid_request', description:string}}
 */
export function validateAuthorizeParams({ state, nonce, scope, code_challenge, code_challenge_method } = {}) {
  // AP2-04 (#77): `scope[]=…` arrives as an array from the query/body parser
  // and used to blow up in `.split()` — a client error, not a TypeError.
  const e = checkOpaque('state', state, STATE_MAX_LENGTH) || checkOpaque('nonce', nonce, NONCE_MAX_LENGTH) ||
            checkOpaque('scope', scope, SCOPE_MAX_LENGTH);
  if (e) return e;

  if (code_challenge !== undefined && code_challenge !== null && code_challenge !== '') {
    if (typeof code_challenge !== 'string') return fail('code_challenge must be a single string value.');
    if (code_challenge.length < CODE_CHALLENGE_MIN_LENGTH || code_challenge.length > CODE_CHALLENGE_MAX_LENGTH ||
        !CODE_CHALLENGE_RE.test(code_challenge)) {
      return fail(`code_challenge must be ${CODE_CHALLENGE_MIN_LENGTH}–${CODE_CHALLENGE_MAX_LENGTH} characters of [A-Za-z0-9._~-] (RFC 7636 §4.2).`);
    }
  }

  if (code_challenge_method !== undefined && code_challenge_method !== null && code_challenge_method !== '') {
    if (typeof code_challenge_method !== 'string' || !CODE_CHALLENGE_METHODS.includes(code_challenge_method)) {
      return fail(`code_challenge_method must be one of ${CODE_CHALLENGE_METHODS.join(', ')}.`);
    }
  }

  return { ok: true };
}

/** `state` as it may be echoed in an error redirect: capped so an over-long value never bounces back at full length. */
export function stateForErrorRedirect(state) {
  if (typeof state !== 'string' || !state) return '';
  return state.length > STATE_MAX_LENGTH ? state.slice(0, STATE_MAX_LENGTH) : state;
}

/** Body parameters of POST /hhttps/oauth/token that must be strings when present. */
export const TOKEN_STRING_PARAMS = Object.freeze([
  'grant_type', 'code', 'redirect_uri', 'client_id', 'client_secret', 'code_verifier', 'refresh_token'
]);

/**
 * AP2-04 (#77): the token endpoint hashes `client_secret` / `code_verifier`
 * and compares `code` / `redirect_uri` / `refresh_token` — an array, object
 * or number in any of them threw an unhandled TypeError (request hung, code
 * consumed). Every present value must be a plain string.
 * @returns {{ok:true} | {ok:false, error:'invalid_request', description:string}}
 */
export function validateTokenParams(body = {}) {
  for (const name of TOKEN_STRING_PARAMS) {
    const value = body[name];
    if (value === undefined || value === null) continue;
    if (typeof value !== 'string') return fail(`${name} must be a single string value.`);
  }
  return { ok: true };
}
