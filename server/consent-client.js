// Browser side of the OAuth consent page (renderConsentPage in server.js).
//
// AP2-31 (#165): this used to be ~150 lines of JavaScript inside a template
// literal — invisible to ESLint and only testable by regex-matching server.js.
// It now lives in its own module:
//
//   * the browser loads it as an ES module from /hhttps/oauth/consent.js
//     (served by server.js straight from this file);
//   * server.js imports CONSENT_I18N / SCOPE_ICONS from here to render the
//     server-side scope rows, so the labels exist exactly once.
//
// Everything the page needs from the server arrives through the JSON block
// <script type="application/json" id="consent-config">{ base, params }</script>
// — no value is ever interpolated into executable code.

/** Emoji per scope (not translated — the labels live in CONSENT_I18N). */
export const SCOPE_ICONS = Object.freeze({
  openid:              '🆔',
  role:                '🎭',
  verification_method: '🔐',
  age_group:           '🔞',
  email:               '✉️'
});

// ─── Consent page i18n (DE/EN toggle, shared storage key) ──────────────────
export const CONSENT_I18N = {
  de: {
    "consent.verified":"✓ Verifizierte Plattform","consent.unverified":"⚠ Nicht verifiziert",
    "consent.warnStrong":"Achtung — Diese Plattform ist nicht von hhttps.org geprüft.",
    "consent.warnB1":"Klicke nur auf „Erlauben“, wenn du der Plattform",
    "consent.warnB2":"wirklich vertraust. Prüfe besonders, ob die URL in der Adressleiste mit",
    "consent.warnB3":"übereinstimmt.","consent.heading":"möchte deine Identität sehen",
    "consent.scopeHead":"Folgende Daten werden geteilt","consent.deny":"Ablehnen","consent.allow":"Erlauben",
    "consent.pseudoLabel":"Anzeigename (frei wählbar, optional)","consent.pseudoHint":"Muss nicht dein echter Name sein. Du entscheidest, was du preisgibst.",
    "consent.footPre":"Keine persönlichen Daten. Du kannst die Verbindung jederzeit auf",
    "consent.footPost":"widerrufen.","consent.processing":"Wird verarbeitet…",
    "consent.errorPrefix":"Fehler: ",
    "scope.unknown.title":"Unbekannter Scope","scope.unknown.desc":"Unbekannter Scope.",
    "scope.openid.title":"Anonyme Identität","scope.openid.desc":"Eine pseudonyme Kennung, die nur diese Plattform sieht.",
    "scope.role.title":"Berufsrolle","scope.role.desc":"Deine verifizierte Berufsrolle — nur falls vorhanden (z. B. per EUDI-Wallet).",
    "scope.verification_method.title":"Verifikationsmethode","scope.verification_method.desc":"Wie deine Rolle verifiziert wurde (z. B. ORCID, Presseausweis).",
    "scope.age_group.title":"Altersgruppe","scope.age_group.desc":"Deine grobe Altersgruppe (z. B. 18+), nicht dein Geburtsdatum. Aktuell Eigenangabe.",
    "scope.email.title":"E-Mail-Adresse","scope.email.desc":"Deine verifizierte E-Mail-Adresse wird an diese Plattform übertragen."
  },
  en: {
    "consent.verified":"✓ Verified platform","consent.unverified":"⚠ Not verified",
    "consent.warnStrong":"Caution — this platform has not been checked by hhttps.org.",
    "consent.warnB1":"Only click “Allow” if you really trust the platform",
    "consent.warnB2":". Check in particular that the URL in the address bar matches",
    "consent.warnB3":".","consent.heading":"wants to see your identity",
    "consent.scopeHead":"The following data will be shared","consent.deny":"Deny","consent.allow":"Allow",
    "consent.pseudoLabel":"Display name (your choice, optional)","consent.pseudoHint":"It does not have to be your real name. You decide what to reveal.",
    "consent.footPre":"No personal data is shared. You can revoke the connection any time at",
    "consent.footPost":".","consent.processing":"Processing…",
    "consent.errorPrefix":"Error: ",
    "scope.unknown.title":"Unknown scope","scope.unknown.desc":"Unknown scope.",
    "scope.openid.title":"Anonymous identity","scope.openid.desc":"A pseudonymous identifier that only this platform sees.",
    "scope.role.title":"Professional role","scope.role.desc":"Your verified professional role — only if present (e.g. via EUDI wallet).",
    "scope.verification_method.title":"Verification method","scope.verification_method.desc":"How your role was verified (e.g. ORCID, press card).",
    "scope.age_group.title":"Age group","scope.age_group.desc":"Your rough age group (e.g. 18+), not your date of birth. Currently self-declared.",
    "scope.email.title":"E-mail address","scope.email.desc":"Your verified e-mail address is passed on to this platform."
  }
};

/** Label/description/icon of one scope in `lang` (DE is the fallback). */
export function scopeLabel(scope, lang = 'de') {
  const table = CONSENT_I18N[lang] || CONSENT_I18N.de;
  const key = table[`scope.${scope}.title`] ? scope : 'unknown';
  return {
    icon:  SCOPE_ICONS[scope] || '?',
    title: key === 'unknown' ? scope : table[`scope.${scope}.title`],
    desc:  table[`scope.${key}.desc`]
  };
}

// ───────────────────────────────────────────────────────────────────────────
// Everything below only ever runs in a browser. Under Node (server.js
// importing the tables above) `document` is undefined and nothing executes.
// ───────────────────────────────────────────────────────────────────────────

let CONSENT_LANG = 'de';
export function t(k) {
  return (CONSENT_I18N[CONSENT_LANG] || CONSENT_I18N.de)[k] ?? (CONSENT_I18N.de[k] ?? k);
}

/** { base, params } from the <script type="application/json"> block. */
function readConfig() {
  try {
    const el = document.getElementById('consent-config');
    const cfg = JSON.parse(el.textContent);
    return { base: cfg.base || '', params: new URLSearchParams(cfg.params || '') };
  } catch {
    return { base: '', params: new URLSearchParams('') };
  }
}

export function initConsentPage() {
  // AP2-07 (#87): the server's own base URL (BASE_URL) — never a hard-coded host.
  const { base: HHTTPS_BASE, params } = readConfig();

  function applyConsentLang(lang) {
    CONSENT_LANG = CONSENT_I18N[lang] ? lang : 'de';
    document.documentElement.lang = CONSENT_LANG;
    document.querySelectorAll('[data-i18n]').forEach(function (e) {
      const v = t(e.getAttribute('data-i18n'));
      if (v != null) e.textContent = v;
    });
    document.querySelectorAll('.lang-toggle button').forEach(function (b) {
      b.classList.toggle('active', b.dataset.lang === CONSENT_LANG);
    });
    try { localStorage.setItem('iamhmn-lang', CONSENT_LANG); } catch { /* storage blocked */ }
  }

  function detectConsentLang() {
    try {
      const sv = localStorage.getItem('iamhmn-lang');
      if (sv && CONSENT_I18N[sv]) return sv;
    } catch { /* storage blocked */ }
    const n = (navigator.language || 'de').slice(0, 2).toLowerCase();
    return CONSENT_I18N[n] ? n : 'de';
  }

  // Read a JWT payload without verifying (client-side, for the exp check only).
  function jwtPayload(tok) {
    try { return JSON.parse(atob(tok.split('.')[1].replace(/-/g, '+').replace(/_/g, '/'))); }
    catch { return null; }
  }
  // Expired (with a small clock-skew margin) or unreadable → treat as expired.
  function hhttpsTokenExpired(tok) {
    const p = jwtPayload(tok);
    if (!p || !p.exp) return true;
    return (p.exp * 1000) <= (Date.now() + 5000);
  }
  function clearIdentity() {
    try { localStorage.removeItem('hhttps_identity'); } catch { /* storage blocked */ }
  }

  // AK-30: hand login_hint/pseudonym (if the platform sent them, AK-29) on to
  // the sign-in page as their own query params so it can pre-fill and
  // auto-send the code (AK-31); returnTo brings the user back here.
  function relogin() {
    clearIdentity();
    let url = HHTTPS_BASE + '/?returnTo=' + encodeURIComponent(window.location.href);
    const loginHint = params.get('login_hint');
    const pseudonym = params.get('pseudonym');
    if (loginHint) url += '&login_hint=' + encodeURIComponent(loginHint);
    if (pseudonym) url += '&pseudonym=' + encodeURIComponent(pseudonym);
    window.location = url;
  }

  // Try to mint a fresh access token from the stored refresh token. Returns the
  // new access token, or null if refresh is impossible (then we re-login).
  async function tryRefresh(identity) {
    if (!identity || !identity.refreshToken) return null;
    if (identity.refreshExpiresAt && new Date(identity.refreshExpiresAt).getTime() <= Date.now()) return null;
    try {
      const r = await fetch(HHTTPS_BASE + '/hhttps/token/refresh', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken: identity.refreshToken })
      });
      if (!r.ok) return null;
      const d = await r.json();
      if (!d.token) return null;
      // AP3-18 (#116): /hhttps/token/refresh rotates. Without adopting the new
      // refresh token here, the consent page would write the INVALIDATED one back
      // into the shared localStorage['hhttps_identity'] and break the sign-in
      // page's silent refresh too.
      const merged = Object.assign({}, identity, {
        token: d.token,
        expiresAt: d.expiresAt || identity.expiresAt || null,
        refreshToken: d.refreshToken || identity.refreshToken,
        refreshExpiresAt: d.refreshExpiresAt || identity.refreshExpiresAt || null
      });
      try { localStorage.setItem('hhttps_identity', JSON.stringify(merged)); } catch { /* storage blocked */ }
      return d.token;
    } catch { return null; }
  }

  /** AP2-31: the /approve request body — built once, used for both attempts. */
  function approveBody(token) {
    return JSON.stringify({
      token,
      client_id:             params.get('client_id'),
      redirect_uri:          params.get('redirect_uri'),
      scope:                 params.get('scope'),
      state:                 params.get('state'),
      nonce:                 params.get('nonce'),
      code_challenge:        params.get('code_challenge'),
      code_challenge_method: params.get('code_challenge_method'),
      pseudonym:             (document.getElementById('pseudoInput') || {}).value || null
    });
  }
  function postApprove(token) {
    return fetch('/hhttps/oauth/approve', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: approveBody(token)
    });
  }

  // AP2-33 (#175): /approve answers with RFC 6749/6750 codes — an expired or
  // revoked HHTTPS token is `invalid_token`. The free-text match stays as a
  // fallback for an older server still answering with a bare message.
  function isTokenExpiry(d) {
    if (d && d.error === 'invalid_token') return true;
    return /expired|jwt/i.test((d && d.error || '') + ' ' + (d && d.error_description || ''));
  }

  document.getElementById('denyBtn').addEventListener('click', () => {
    const redirectUri = params.get('redirect_uri');
    const state = params.get('state') || '';
    const url = new URL(redirectUri);
    url.searchParams.set('error', 'access_denied');
    url.searchParams.set('error_description', 'User denied the request');
    if (state) url.searchParams.set('state', state);
    window.location = url.toString();
  });

  document.getElementById('allowBtn').addEventListener('click', async () => {
    const allow = document.getElementById('allowBtn');
    const status = document.getElementById('status');
    allow.disabled = true;
    allow.textContent = t('consent.processing');

    // Identity is published to localStorage by the sign-in page after a token
    // is issued (publishIdentity). Without it we send the user there and come
    // back via ?returnTo=.
    let identity = null;
    try {
      const raw = localStorage.getItem('hhttps_identity');
      if (raw) identity = JSON.parse(raw);
    } catch { /* storage blocked */ }

    if (!identity || !identity.token) {
      // No identity at all → straight to sign-in (no error shown).
      relogin();
      return;
    }

    // Expired access token → silently refresh, or re-login. The user never sees
    // an "expired" error.
    if (hhttpsTokenExpired(identity.token)) {
      const fresh = await tryRefresh(identity);
      if (fresh) {
        identity.token = fresh;
      } else {
        relogin();
        return;
      }
    }

    try {
      const r = await postApprove(identity.token);
      const d = await r.json();
      if (!r.ok) {
        // Server-side expiry (race between our check and the request): try one
        // refresh, then re-login — never surface an expiry error to the user.
        if (isTokenExpiry(d)) {
          const fresh = await tryRefresh(identity);
          if (fresh) {
            const r2 = await postApprove(fresh);
            const d2 = await r2.json();
            if (r2.ok) { window.location = d2.redirect; return; }
          }
          relogin();
          return;
        }
        throw new Error(d.error_description || d.error || 'OAuth error');
      }
      window.location = d.redirect;
    } catch (e) {
      status.className = 'status error';
      status.textContent = t('consent.errorPrefix') + e.message;
      allow.disabled = false;
      allow.textContent = t('consent.allow');
    }
  });

  document.querySelectorAll('.lang-toggle button').forEach(function (b) {
    b.addEventListener('click', function () { applyConsentLang(b.dataset.lang); });
  });
  applyConsentLang(detectConsentLang());

  // AK-30: pre-fill the display name from the platform's pseudonym hint — via
  // the DOM (never interpolated into the HTML).
  const pi = document.getElementById('pseudoInput');
  if (pi && !pi.value) pi.value = params.get('pseudonym') || '';

  // Hide the `role` row for an identity that carries no role at all.
  try {
    const idn = JSON.parse(localStorage.getItem('hhttps_identity') || 'null');
    if (!idn || !idn.role) {
      const rr = document.querySelector('.scope-row[data-scope="role"]');
      if (rr) rr.style.display = 'none';
    }
  } catch { /* storage blocked */ }
}

if (typeof document !== 'undefined') initConsentPage();
