// identity.js — pure helpers for the email-anchored identity feature (spec: docs/specs/email-anchored-identity).
// No I/O, no DB, no Express: everything here is unit-testable in isolation.
import crypto from 'node:crypto';

const DEV_PEPPER = 'dev-pepper';
let warnedMissingPepper = false;

/** AK-2 / D1: trim + lowercase (no dot/plus normalization). null/undefined → ''. */
export function normalizeEmail(email) {
  if (email === null || email === undefined) return '';
  return String(email).trim().toLowerCase();
}

/** D1: hex HMAC-SHA256(pepper, normalizeEmail(email)). Missing pepper → warn once, use 'dev-pepper'. */
export function emailAnchorHash(email, pepper = process.env.HHTTPS_VERIFICATION_PEPPER) {
  let key = pepper;
  if (!key) {
    if (!warnedMissingPepper) {
      warnedMissingPepper = true;
      console.warn('[identity] HHTTPS_VERIFICATION_PEPPER is not set — using insecure fallback pepper (dev only).');
    }
    key = DEV_PEPPER;
  }
  return crypto.createHmac('sha256', key).update(normalizeEmail(email)).digest('hex');
}

/**
 * F-4 (S-5): in production the pepper is mandatory — without it every anchor
 * hash would be computed with the public 'dev-pepper' (dictionary-attackable)
 * and a later rotation would silently detach all anchors. Called once at boot.
 */
export function assertPepperConfigured(env = process.env) {
  if (env.NODE_ENV === 'production' && !env.HHTTPS_VERIFICATION_PEPPER) {
    throw new Error('HHTTPS_VERIFICATION_PEPPER must be set in production (identity anchors depend on it).');
  }
}

/** AK-6: charset [\w\-. äöüÄÖÜß], max 32 chars, trimmed. Empty → null. */
export function sanitizePseudonym(input) {
  if (input === null || input === undefined) return null;
  return String(input).replace(/[^\w\-. äöüÄÖÜß]/gu, '').slice(0, 32).trim() || null;
}

const PSEUDONYM_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789';

/** AK-7: 'iamhmn_' + 10 × [a-z0-9] via crypto.randomInt. */
export function generatePseudonym() {
  let s = '';
  for (let i = 0; i < 10; i++) s += PSEUDONYM_ALPHABET[crypto.randomInt(PSEUDONYM_ALPHABET.length)];
  return `iamhmn_${s}`;
}

/** AK-6/AK-7: sanitized user pseudonym, or a generated one if empty. */
export function resolvePseudonym(input) {
  return sanitizePseudonym(input) ?? generatePseudonym();
}

/** AK-23 / D7: strip whitespace and hyphens; always returns a string. */
export function normalizeCode(input) {
  if (input === null || input === undefined) return '';
  return String(input).replace(/[\s-]/g, '');
}

/** AK-24: exactly 6 digits after normalization. */
export function isValidCode(code) {
  return /^\d{6}$/.test(normalizeCode(code));
}

const FLAG_METHODS = ['email', 'passkey', 'github', 'eudi'];

/** AK-18 / D5: derive *_verified booleans from a verified_methods array. Non-array → all false. */
export function methodFlags(methods) {
  const list = Array.isArray(methods) ? methods : [];
  const flags = {};
  for (const m of FLAG_METHODS) flags[`${m}_verified`] = list.includes(m);
  return flags;
}

/**
 * AK-17 / AK-18 / W-2: the identity claim bundle handed to OAuth clients —
 * used by the code grant, the refresh grant and /userinfo alike.
 *   verified_methods  — the array as-is (non-array → [])
 *   *_verified flags  — derived via methodFlags()
 *   preferred_username — the account pseudonym (only when present)
 *   email              — only with scope `email` AND a known address; an
 *                        address is cached only after proof, so it also
 *                        forces email_verified = true.
 */
export function buildIdentityClaims({ methods, pseudonym, email, scopes } = {}) {
  const list = Array.isArray(methods) ? methods : [];
  const scopeList = Array.isArray(scopes) ? scopes : [];
  return {
    verified_methods: list,
    ...methodFlags(list),
    ...(pseudonym ? { preferred_username: pseudonym } : {}),
    ...(scopeList.includes('email') && email ? { email, email_verified: true } : {})
  };
}

/**
 * F-2 (K-3/S-2): decide the identity of a freshly authenticated passkey session.
 * The credential row is the ONLY source of truth for the userId — the userId
 * parked by /webauthn/auth/start comes from the request body and may be an
 * attacker's value. A prior session is merged only when it belongs to the
 * same user; a foreign prior session is ignored (never merged, never deleted).
 *
 * @returns {{ userId: string, priorMerge: object } | { error: 'credential_user_mismatch' }}
 */
export function resolvePasskeySession({ storedUserId, cred, prior }) {
  const userId = cred?.userId;
  if (!userId) return { error: 'credential_user_mismatch' };
  if (storedUserId && storedUserId !== userId) return { error: 'credential_user_mismatch' };

  let priorMerge = {};
  if (prior && prior.userId === userId) {
    priorMerge = {
      ...(prior.emailVerified ? {
        emailVerified:   true,
        emailDomain:     prior.emailDomain     || null,
        emailLevel:      prior.emailLevel      || null,
        emailTrustBonus: prior.emailTrustBonus || 0,
      } : {}),
      ...(prior.githubVerified ? { githubVerified: true } : {}),
      ...(prior.eudiVerified   ? { eudiVerified:   true } : {}),
      ...(prior.pseudonym      ? { pseudonym: prior.pseudonym } : {}),
    };
  }
  return { userId, priorMerge };
}
