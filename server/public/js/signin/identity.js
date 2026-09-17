/* AP8-36 (#223): ONE place that writes `localStorage['hhttps_identity']`.
   ──────────────────────────────────────────────────────────────────────────
   The record used to be assembled at three different spots (human token,
   machine token, sites/hhttps.html) with drifting field sets. This module is
   the schema; every producer goes through buildIdentity()/buildMachineIdentity().

   hhttps_identity — schema v1 (unversioned on the wire for compatibility)
   ─────────────────────────────────────────────────────────────────────────
   token             string   HHTTPS access token (JWT). REQUIRED.
   refreshToken      string?  Long-lived refresh token, issuer origin only.
   role              string?  Role / occupation id, null when none was declared.
   roleLabel         string?  Human-readable role label.
   roleIcon          string?  Emoji for the role ('🤖' for machines).
   roleLevel         string?  Assurance level id of the role.
   levelLabel        string?  Human-readable assurance level.
   trustScore        number   Server-issued score; ALWAYS 0 for actorType 'bot'.
   actorType         string   'human' | 'bot'.
   method            string   Comma list of confirmed methods — legacy shape,
                              kept for the extension and older pages.
   verified_methods  string[] Structured form of `method`. Consumers should
                              prefer this; `method` is the compatibility field.
   operatorEmail     string?  Machine identities only: the operator on file.
   issuer            string   'hhttps://hhttps.org' — the HHTTPS scheme form.
                              Consumers (extension background.js/popup.js,
                              content-issuer.js, the consent page) map it back
                              to https:// themselves; see ISSUER_URL below.
   issuedAt          string   ISO timestamp, set by the producer.
   expiresAt         string?  ISO expiry of `token`.
   refreshExpiresAt  string?  ISO expiry of `refreshToken`.                */

export const STORAGE_KEY = 'hhttps_identity';
export const ISSUER_HOST = 'hhttps.org';
/** The value written to `issuer` (HHTTPS scheme form). */
export const ISSUER = 'hhttps://' + ISSUER_HOST;
/** The same issuer as a real URL — what every consumer recomputes today. */
export const ISSUER_URL = 'https://' + ISSUER_HOST;

/* AP8-20 (#173): the refresh token stays client-held by design (zero-PII, no
   server-side session). Two hardenings that cost no UX:
   (1) it is only ever persisted on the ISSUER's own origin. A mirror, a
       staging host or a local copy of this page gets the short-lived access
       token only — the long-lived credential never lands in a foreign
       origin's localStorage.
   (2) a refresh token whose refreshExpiresAt has passed is dropped instead of
       lingering in storage; it cannot buy a new token any more anyway. */
export const ISSUER_HOSTS = [ISSUER_HOST, 'www.' + ISSUER_HOST];

export function isIssuerOrigin(hostname) {
  const h = String(hostname || '');
  return ISSUER_HOSTS.indexOf(h) >= 0 || h === 'localhost' || h === '127.0.0.1';
}

export function storableRefreshToken(tok, refreshExpiresAt, hostname, now) {
  if (!tok) return null;
  if (!isIssuerOrigin(hostname)) return null;
  const at = now === undefined ? Date.now() : now;
  if (refreshExpiresAt && new Date(refreshExpiresAt).getTime() <= at) return null;
  return tok;
}

/**
 * Identity record for a HUMAN token, built from the /hhttps/role/declare
 * response `d` and the list of confirmed methods.
 * `refreshToken` must already have gone through storableRefreshToken().
 */
export function buildIdentity(d, methods, refreshToken, issuedAt) {
  const h = (d && d.hhttps) || {};
  const role = (d && d.role) || null;
  return {
    token:            h.token,
    refreshToken:     refreshToken || null,
    role:             (role && (role.id || role.role)) || h.role || null,
    roleLabel:        (role && role.label) || null,
    roleIcon:         (role && role.icon) || null,
    roleLevel:        (role && role.level) || null,
    levelLabel:       (role && role.levelLabel) || null,
    trustScore:       h.trustScore || 0,
    actorType:        'human',
    method:           (methods || []).join(',') || 'email',
    verified_methods: (methods || []).slice(),
    issuer:           ISSUER,
    issuedAt:         issuedAt || new Date().toISOString(),
    expiresAt:        h.expiresAt || null,
    refreshExpiresAt: h.refreshExpiresAt || null
  };
}

/** Identity record for a MACHINE token — actorType 'bot', trustScore 0. */
export function buildMachineIdentity(td, operatorEmail, issuedAt) {
  return {
    token:            (td && td.token) || null,
    refreshToken:     null,
    role:             null,
    roleLabel:        null,
    roleIcon:         '🤖',
    roleLevel:        null,
    levelLabel:       null,
    trustScore:       0,
    actorType:        'bot',
    method:           'machine',
    verified_methods: ['machine'],
    operatorEmail:    operatorEmail || null,
    issuer:           ISSUER,
    issuedAt:         issuedAt || new Date().toISOString(),
    expiresAt:        (td && td.expiresAt) || null,
    refreshExpiresAt: null
  };
}

/* AP8-17 (#151): returnTo is only honoured when it stays on THIS origin —
   the OAuth consent page lives here, so a relative path or an absolute URL
   of the same origin is all we ever need. Other hosts, protocol-relative
   URLs (//evil), javascript:, data: … resolve to null and are ignored. */
export function resolveReturnTo(raw, origin) {
  if (!raw || typeof raw !== 'string') return null;
  let t;
  try { t = new URL(raw, origin); } catch { return null; }
  if (t.protocol !== 'https:' && t.protocol !== 'http:') return null;
  if (t.origin !== origin) return null;
  return t;
}
