// server/client-registration.js
//
// AP5-38 (Review 2026-09, Welle 3): the ONE source for the helpers that decide
// what a registered OAuth client may look like. They used to exist twice —
// once in server.js (developer portal) and once in wp-plugin-registration.js
// (WordPress plugin) — with *different* semantics, so the same input produced
// different client_ids, a different apex domain (and therefore a different
// `_hhttps-verify.<apex>` host) and different redirect-URI verdicts depending
// on which door a registration came through.
//
// Where the two copies disagreed, the STRICTER rule won:
//
//   • TWO_PART_TLDS: 23 entries instead of 10. The short list did not know
//     `gov.uk`, so `https://stadt.gov.uk` collapsed to the apex `gov.uk` and
//     the plugin asked the site owner to put the TXT record at
//     `_hhttps-verify.gov.uk` — a host they cannot control, and a record any
//     other `*.gov.uk` site could have satisfied. A longer suffix list can
//     only ever make the apex MORE specific, never less.
//
//   • apexDomainFromUrl requires at least two labels. A single-label host
//     ("localhost") is not a zone anyone can publish a verification TXT
//     record under, so it must not be accepted as a platform apex.
//
//   • isValidRedirectUri: https (or http on localhost/127.0.0.1 for dev),
//     no fragment, no embedded credentials, length-capped. RFC 6749 §3.1.2
//     says the redirection endpoint MUST NOT include a fragment, so the
//     plugin's fragment rule is the correct one; the portal's scheme rule is
//     the correct one (the plugin allowed ANY scheme as long as the host was
//     `localhost`). Both are kept, which is the intersection of the two.
//
//   • generateClientId: one implementation with an optional prefix. The tail
//     is 8 base64url characters (48 bit) instead of the portal's 4 hex
//     characters (16 bit) — client_id is a public identifier and 16 bit
//     collides in practice.
//
// Zero-PII: nothing here stores or logs anything; these are pure functions.

import crypto from 'crypto';

// Heuristic public-suffix list for the common two-part TLDs. Not the full PSL,
// but it covers the domains real registrations use. Adding an entry makes the
// resulting apex more specific — never less — so this list is safe to grow.
export const TWO_PART_TLDS = new Set([
  'co.uk', 'co.jp', 'co.kr', 'co.nz', 'co.za', 'co.in', 'co.il',
  'com.au', 'com.br', 'com.cn', 'com.mx', 'com.tr', 'com.tw', 'com.ar',
  'org.uk', 'org.au', 'net.au', 'gov.uk', 'gov.au', 'ac.uk', 'ac.jp',
  'or.jp', 'ne.jp'
]);

/**
 * Normalize a hostname to its "apex" form for binding purposes.
 * reddit.com, www.reddit.com, old.reddit.com, np.reddit.com → "reddit.com"
 * A single-label host is returned unchanged (callers that need a real zone
 * use apexDomainFromUrl, which rejects it).
 */
export function normalizeApexDomain(hostname) {
  if (!hostname || typeof hostname !== 'string') return null;
  let h = hostname.toLowerCase().trim();
  // Strip protocol and path if accidentally included
  h = h.replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '');
  if (!/^[a-z0-9.-]+$/.test(h)) return null;
  const parts = h.split('.').filter(Boolean);
  if (parts.length < 2) return parts.join('.') || null;
  if (parts.length >= 3) {
    const lastTwo = parts.slice(-2).join('.');
    if (TWO_PART_TLDS.has(lastTwo)) return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

/** Apex domain of a URL or bare host, or null. Needs at least two labels —
 *  a registration apex must be a zone the owner can publish TXT records in. */
export function apexDomainFromUrl(urlOrHost) {
  if (!urlOrHost || typeof urlOrHost !== 'string') return null;
  let host;
  try {
    host = new URL(urlOrHost.includes('://') ? urlOrHost : `https://${urlOrHost}`).hostname;
  } catch { return null; }
  const apex = normalizeApexDomain(host);
  return apex && apex.includes('.') ? apex : null;
}

/** Apex domain of an e-mail address, or null. */
export function apexDomainFromEmail(email) {
  if (typeof email !== 'string' || !email.includes('@')) return null;
  return apexDomainFromUrl(email.split('@')[1]);
}

/** Variant A: the e-mail's apex must equal the platform's apex.
 *  Subdomain mail is accepted (admin@team.example.com for example.com). */
export function emailMatchesPlatform(email, homepageUrl) {
  const e = apexDomainFromEmail(email);
  const h = apexDomainFromUrl(homepageUrl);
  return !!(e && h && e === h);
}

/** The DNS host a platform must publish its verification TXT record at. */
export function expectedDnsHost(apex) {
  return apex ? `_hhttps-verify.${apex}` : null;
}

export const MAX_REDIRECT_URI_LENGTH = 500;
export const MAX_HOMEPAGE_URL_LENGTH = 500;   // oauth_clients.homepage_url is VARCHAR(500)

/** AP5-14: both registration paths answered "homepage_url must be a valid
 *  HTTPS URL" while only checking that an apex could be derived — `http://…`
 *  and even `ftp://…` passed. The message was right; the check was not. */
export function isValidHomepageUrl(value) {
  if (typeof value !== 'string' || !value || value.length > MAX_HOMEPAGE_URL_LENGTH) return false;
  let u;
  try { u = new URL(value); } catch { return false; }
  if (u.protocol !== 'https:') return false;
  if (u.username || u.password) return false;
  return !!apexDomainFromUrl(value);
}

/** Validate a redirect URI. https, or http on localhost/127.0.0.1 for dev;
 *  no fragment (RFC 6749 §3.1.2), no credentials, length-capped. */
export function isValidRedirectUri(uri) {
  if (typeof uri !== 'string' || !uri || uri.length > MAX_REDIRECT_URI_LENGTH) return false;
  let u;
  try { u = new URL(uri); } catch { return false; }
  if (u.hash) return false;
  if (u.username || u.password) return false;
  if (u.protocol === 'https:') return true;
  return u.protocol === 'http:' && (u.hostname === 'localhost' || u.hostname === '127.0.0.1');
}

// AP5-44: two values that both registration paths hard-coded as literals.
/** owner_user_id of every client registered through the CMS-plugin path.
 *  It is a sentinel, not a user id — no HHTTPS identity owns these rows. */
export const WP_PLUGIN_OWNER_ID = 'wp-plugin';
/** How long a platform's e-mail confirmation link stays valid. */
export const PLATFORM_EMAIL_TOKEN_TTL_MS = 48 * 3600 * 1000;

/** URL-safe random token. `bytes` is entropy, not output length. */
export function randomToken(bytes = 24) {
  return crypto.randomBytes(bytes).toString('base64url');
}

const MAX_SLUG_LENGTH = 32;

/** Slug-ify a platform name into a client_id: "my-platform-Ab3xK9-c".
 *  @param {string} name      platform / site name
 *  @param {object} [opts]
 *  @param {string} [opts.prefix]    e.g. 'wp-' for plugin registrations
 *  @param {string} [opts.fallback]  slug used when the name has no usable characters
 */
export function generateClientId(name, { prefix = '', fallback = 'platform' } = {}) {
  const slug = String(name || fallback)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, MAX_SLUG_LENGTH);
  return `${prefix}${slug || fallback}-${randomToken(6)}`;
}
