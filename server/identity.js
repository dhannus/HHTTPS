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
