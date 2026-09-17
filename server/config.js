// config.js — AP3-36 (#169): the ONE place where the issuer's public identity
// is read from the environment.
//
// Both server.js and email.js used to derive a `BASE_URL` of their own, with
// DIFFERENT fallbacks: server.js fell back to ORIGIN (and thus to RP_ID),
// email.js to the hard-coded literal 'https://hhttps.org'. An issuer running
// under any other RP_ID therefore shipped verified/rejected/admin mails that
// pointed at hhttps.org. One resolver, one answer.
//
// The resolvers take an explicit `env` so they stay unit-testable; the module
// constants are the values this process booted with.

/** RP_ID — the WebAuthn relying-party id and the issuer's host name. */
export function resolveRpId(env = process.env) {
  return env.RP_ID || 'hhttps.org';
}

/** ORIGIN — the scheme+host WebAuthn ceremonies are expected to come from. */
export function resolveOrigin(env = process.env) {
  return env.ORIGIN || `https://${resolveRpId(env)}`;
}

/** BASE_URL — the public base of every link this issuer puts into a mail or a redirect. */
export function resolveBaseUrl(env = process.env) {
  return env.BASE_URL || resolveOrigin(env);
}

export const RP_ID    = resolveRpId();
export const ORIGIN   = resolveOrigin();
export const BASE_URL = resolveBaseUrl();
