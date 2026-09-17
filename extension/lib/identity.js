/**
 * HHTTPS Extension — pure identity helpers.
 *
 * AP8-47 (#246) / AP8-53 (#249): everything here is free of extension APIs, so
 * unit tests (server/test/unit/extension.test.mjs) can import and call it, and
 * so the issuer base URL is derived in ONE place instead of six.
 */

/** The issuer the extension talks to when an identity carries none. */
export const ISSUER_BASE = 'https://hhttps.org';
/** Keys in the extension's local storage area. */
export const STORAGE_IDENTITIES = 'hhttps_identities';
export const STORAGE_ACTIVE_ID  = 'hhttps_active_id';
export const STORAGE_SIGN_MODE  = 'hhttps_sign_mode';
/** Refresh the access token this long before it expires. */
export const REFRESH_AHEAD_MS = 5 * 60_000;
export const ALARM_PREFIX = 'refresh_';

/**
 * AP8-36 (#223): `hhttps_identity.issuer` is written in the HHTTPS scheme form
 * (`hhttps://hhttps.org`). Every caller used to map it back to https:// with
 * its own inline `.replace()`; this is that mapping, once.
 */
export function issuerBase(identity) {
  const raw = (identity && identity.issuer) || ISSUER_BASE;
  return String(raw).replace(/^hhttps:\/\//, 'https://').replace(/\/+$/, '');
}

/** Decoded JWT payload, or null when the token is unreadable. */
export function decodeJwtPayload(token) {
  try {
    const p = String(token).split('.')[1];
    const padded = p + '='.repeat((4 - p.length % 4) % 4);
    return JSON.parse(atob(padded.replace(/-/g, '+').replace(/_/g, '/')));
  } catch (e) {
    return null;
  }
}

/**
 * AP8-05 (#80): the id used to be `issuer#role`. Since v0.5 the server no
 * longer echoes a role (`role: null`), so every identity — human AND bot —
 * collapsed onto `issuer#unknown` and overwrote the previous one. The id is
 * now taken from the signed token: actor type plus the stable subject
 * (`userId` for humans, `operatorId` for machines). Both are pseudonymous,
 * and both survive a re-issuance, so re-issuing replaces the right entry.
 */
export function computeIdentityId(identity) {
  const issuer  = (identity && identity.issuer) || 'hhttps://hhttps.org';
  const payload = decodeJwtPayload(identity && identity.token) || {};
  const actor   = payload.actorType || (identity && identity.actorType)
                || (payload.human === false ? 'bot' : payload.human === true ? 'human' : 'unknown');
  const subject = payload.userId || payload.operatorId || payload.sub || payload.jti
                || (identity && identity.role) || 'unknown';
  return `${issuer}#${actor}#${subject}`;
}

/**
 * When the refresh alarm for this identity should fire, in epoch ms.
 * `null` means "do not schedule" (no refresh token or no readable expiry);
 * a value at or below `now` means "refresh right away".
 */
export function refreshFireAt(identity, now = Date.now()) {
  if (!identity || !identity.refreshToken) return null;
  const payload = decodeJwtPayload(identity.token);
  if (!payload || !payload.exp) return null;
  const fireAt = payload.exp * 1000 - REFRESH_AHEAD_MS;
  return fireAt <= now + 1000 ? now : fireAt;
}

export const alarmNameFor = (id) => `${ALARM_PREFIX}${id}`;
export const idFromAlarmName = (name) =>
  (String(name).startsWith(ALARM_PREFIX) ? String(name).slice(ALARM_PREFIX.length) : null);

/** Signature mode for the context menu: 'alpha' (loose) or 'beta' (text-bound). */
export const SIGN_MODES = ['alpha', 'beta'];
export function normaliseSignMode(mode) {
  return SIGN_MODES.includes(mode) ? mode : 'alpha';
}
/** 'beta' binds the signature to the exact text, 'alpha' only to the domain. */
export const bindingTypeFor = (mode) => (normaliseSignMode(mode) === 'beta' ? 'document' : 'web');

/** Merge a refresh response into the stored identity (AP3-18: keep rotation). */
export function applyRefresh(ident, data, now = Date.now()) {
  return {
    ...ident,
    token:            data.token,
    refreshToken:     data.refreshToken || ident.refreshToken,
    trustScore:       (data.role && data.role.trustScore) || ident.trustScore,
    expiresAt:        data.expiresAt || null,
    refreshExpiresAt: data.refreshExpiresAt || ident.refreshExpiresAt,
    lastRefreshAt:    now
  };
}
