/* ============================================================
   HHTTPS Developer Portal — Shared JS  (v5 — passkey gate, no role requirement)
   ============================================================ */

(function () {
  'use strict';

  const LS_UID_KEY      = 'hhttps_uid';
  const LS_IDENTITY_KEY = 'hhttps_identity';
  const LS_LANG_KEY     = 'hhttps_lang';
  const API_BASE = '';

  // ─── i18n  ─────────────────────────────────────────────────────────────
  // Strategy: pages use lang="de" by default. Strings marked with
  // [data-i18n="key"] (text content) or [data-i18n-placeholder="key"] (input
  // placeholder) get swapped on language toggle. Untranslated keys → keep
  // current DOM text (no broken UI). Toggle persists in localStorage.
  const T = {
    de: {
      // nav
      'nav.overview':       'Übersicht',
      'nav.dashboard':      'Dashboard',
      'nav.admin':          'Admin',
      'nav.spec':           'Spec',
      'nav.signin':         'Anmelden',
      'nav.signout':        'Abmelden',
      'nav.github':         'GitHub',
      // dashboard
      'dash.title':         'Meine Plattformen',
      'dash.subtitle':      'Alle Plattformen, die unter deiner HHTTPS-Identität registriert sind.',
      'dash.register':      '+ Plattform registrieren',
      'dash.empty.title':   'Noch keine Plattformen',
      'dash.empty.lead':    'Registriere deine erste Plattform, um HHTTPS-Tokens auszustellen.',
      'dash.integration':   'Integration',
      'dash.integration.lead': 'Sobald eine Plattform den Status verified erreicht, kannst du diese Werte in deinem SDK nutzen.',
      'dash.precond':       'Voraussetzungen für Review',
      'dash.dns.title':     'DNS-Verifikation · TXT-Record',
      'dash.dns.verify':    'DNS jetzt prüfen',
      'dash.dns.copy':      'Wert kopieren',
      'dash.dns.verified':  '✓ Verifiziert',
      'dash.submit':        'Zur Prüfung einreichen →',
      'dash.edit':          'Bearbeiten',
      'dash.delete':        'Löschen',
      'dash.resend':        'E-Mail erneut senden',
      'dash.cancel':        'Abbrechen',
      'dash.save':          'Speichern',
      // checklist items
      'check.email':        'E-Mail bestätigt',
      'check.email.hint':   'Klicke auf den Verifikationslink in deinem Posteingang.',
      'check.domain':       'Kontakt-E-Mail passt zur Plattform-Domain',
      'check.domain.hint':  'Verwende eine E-Mail-Adresse auf der Apex-Domain der Plattform.',
      'check.dns':          'DNS TXT-Record verifiziert',
      'check.dns.hint':     'Setze den unten gezeigten Record und klicke "DNS jetzt prüfen".',
      'check.impressum':    'Impressum-URL gesetzt',
      'check.impressum.hint':'Erforderlich für Review. Bearbeite die Plattform, um sie zu setzen.',
      // statuses
      'status.email_pending':  'E-Mail-Bestätigung ausstehend',
      'status.unverified':     'Unverifiziert · Setup läuft',
      'status.pending_review': 'In Admin-Review',
      'status.verified':       'Verifiziert',
      'status.rejected':       'Abgelehnt',
      'status.suspended':      'Gesperrt',
      // access gate (v5: passkey required, no role requirement)
      'gate.title':         'Passkey erforderlich',
      'gate.lead':          'Das Developer Portal setzt eine Passkey-verifizierte Identität voraus. Eine bestimmte Rolle brauchst du nicht — aber einen Passkey.',
      'gate.why':           'Warum Passkey',
      'gate.why.text':      'Deine user_id wird nur dann bei jeder Anmeldung dieselbe, wenn sie aus einem gespeicherten Passkey stammt. Bei reiner E-Mail-Anmeldung bekommst du jedes Mal eine neue Identität — deine registrierten Plattformen wären danach nicht mehr deine. Zusätzlich: wer eine Plattform betreibt, gegen die sich andere Menschen authentifizieren, sollte selbst hardwaregestützt verifiziert sein.',
      'gate.howto':         'So bekommst du Zugang',
      'gate.step1':         'Gehe zu hhttps.org und registriere einen Passkey (Face ID, Fingerabdruck, Windows Hello oder Sicherheitsschlüssel).',
      'gate.step2':         'Melde dich mit genau diesem Passkey an.',
      'gate.step3':         'Komm zurück — das Portal ist dann sofort nutzbar. Verwende künftig immer denselben Passkey, sonst entsteht eine neue Identität.',
      'gate.cta.signin':    'Zu hhttps.org →',
      'gate.cta.back':      '← Zurück zur Übersicht',
      'gate.methods':       'Aktuell bestätigte Methoden:',
      'gate.methods.none':  'keine',
      'gate.bot.note':      'Du betreibst einen Bot oder Agenten? Maschinen laufen nicht über dieses Portal, sondern über /hhttps/machine/register mit bestätigter Betreiber-E-Mail.',
    },
    en: {
      'nav.overview':       'Overview',
      'nav.dashboard':      'Dashboard',
      'nav.admin':          'Admin',
      'nav.spec':           'Spec',
      'nav.signin':         'Sign in',
      'nav.signout':        'Sign out',
      'nav.github':         'GitHub',
      'dash.title':         'My platforms',
      'dash.subtitle':      'All platforms registered under your HHTTPS identity.',
      'dash.register':      '+ Register platform',
      'dash.empty.title':   'No platforms yet',
      'dash.empty.lead':    'Register your first platform to start issuing HHTTPS verifications.',
      'dash.integration':   'Integration',
      'dash.integration.lead':'Once a platform reaches verified status, point your SDK at these values.',
      'dash.precond':       'Preconditions for review',
      'dash.dns.title':     'DNS verification · TXT record',
      'dash.dns.verify':    'Verify DNS now',
      'dash.dns.copy':      'Copy value',
      'dash.dns.verified':  '✓ Verified',
      'dash.submit':        'Submit for review →',
      'dash.edit':          'Edit',
      'dash.delete':        'Delete',
      'dash.resend':        'Resend email',
      'dash.cancel':        'Cancel',
      'dash.save':          'Save changes',
      'check.email':        'Email confirmed',
      'check.email.hint':   'Click the verification link in your inbox.',
      'check.domain':       'Contact email matches platform domain',
      'check.domain.hint':  'Use an email at the platform’s apex domain.',
      'check.dns':          'DNS TXT record verified',
      'check.dns.hint':     'Set the record below, then click Verify DNS.',
      'check.impressum':    'Impressum URL set',
      'check.impressum.hint':'Required for review. Edit the platform to add it.',
      'status.email_pending':  'Email confirmation pending',
      'status.unverified':     'Unverified · setup in progress',
      'status.pending_review': 'In admin review',
      'status.verified':       'Verified',
      'status.rejected':       'Rejected',
      'status.suspended':      'Suspended',
      'gate.title':         'Passkey required',
      'gate.lead':          'The developer portal requires a passkey-verified identity. No particular role is needed — but a passkey is.',
      'gate.why':           'Why a passkey',
      'gate.why.text':      'Your user_id only stays the same across sign-ins when it derives from a stored passkey. With e-mail-only sign-in you get a new identity every time, and the platforms you registered would no longer be yours. On top of that: whoever operates a platform that other people authenticate against should themselves be hardware-backed.',
      'gate.howto':         'How to get access',
      'gate.step1':         'Go to hhttps.org and register a passkey (Face ID, fingerprint, Windows Hello or a security key).',
      'gate.step2':         'Sign in with that exact passkey.',
      'gate.step3':         'Come back — the portal works immediately. Always use the same passkey; a different one creates a different identity.',
      'gate.cta.signin':    'Go to hhttps.org →',
      'gate.cta.back':      '← Back to overview',
      'gate.methods':       'Currently confirmed methods:',
      'gate.methods.none':  'none',
      'gate.bot.note':      'Running a bot or agent? Machines do not use this portal — they register via /hhttps/machine/register with a confirmed operator e-mail.',
    }
  };

  function getLang() {
    try {
      const stored = localStorage.getItem(LS_LANG_KEY);
      if (stored === 'de' || stored === 'en') return stored;
    } catch (_) {}
    const nav = (navigator.language || 'de').slice(0, 2).toLowerCase();
    return nav === 'en' ? 'en' : 'de';
  }

  function t(key, vars) {
    const lang = getLang();
    let s = (T[lang] && T[lang][key]) || (T.de && T.de[key]) || key;
    if (vars) {
      Object.keys(vars).forEach(k => { s = s.replace(new RegExp(`\\{${k}\\}`, 'g'), vars[k]); });
    }
    return s;
  }

  function applyTranslations(root) {
    root = root || document;
    root.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      const txt = t(key);
      if (txt && txt !== key) el.textContent = txt;
    });
    root.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
      const key = el.getAttribute('data-i18n-placeholder');
      const txt = t(key);
      if (txt && txt !== key) el.setAttribute('placeholder', txt);
    });
    root.querySelectorAll('[data-i18n-html]').forEach(el => {
      const key = el.getAttribute('data-i18n-html');
      const txt = t(key);
      if (txt && txt !== key) el.innerHTML = txt;
    });
  }

  function setLang(lang) {
    if (lang !== 'de' && lang !== 'en') return;
    try { localStorage.setItem(LS_LANG_KEY, lang); } catch (_) {}
    document.documentElement.lang = lang;
    document.querySelectorAll('.lang-toggle button').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.lang === lang);
    });
    applyTranslations();
    // Notify pages that have JS-rendered content
    document.dispatchEvent(new CustomEvent('hhttps:lang-changed', { detail: { lang } }));
  }

  // ─── Auth ──────────────────────────────────────────────────────────────
  function getIdentity() {
    try {
      const raw = localStorage.getItem(LS_IDENTITY_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch (_) { return null; }
  }

  function getToken() {
    const id = getIdentity();
    return id && id.token ? id.token : null;
  }

  function getUid() {
    return localStorage.getItem(LS_UID_KEY);
  }

  function setIdentity(identity) {
    if (identity) localStorage.setItem(LS_IDENTITY_KEY, JSON.stringify(identity));
  }

  function clearAuth() {
    localStorage.removeItem(LS_IDENTITY_KEY);
    localStorage.removeItem(LS_UID_KEY);
  }

  /** Sign out for real: revoke the tokens at the issuer, then drop the local
   *  identity. Best-effort on the network part — a failed revoke must never
   *  leave the user stuck in a session they asked to end.
   *
   *  Note: /developers/ shares an origin with the issuer, so this is a FULL
   *  sign-out, not just a portal one. That is the honest behaviour; anything
   *  narrower would only pretend to log you out. */
  async function signOut(redirectTo) {
    const id = getIdentity() || {};
    const tokens = [id.token, id.refreshToken].filter(Boolean);
    await Promise.all(tokens.map(token =>
      fetch('/hhttps/revoke', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
      }).catch(() => null)
    ));
    clearAuth();
    window.location.href = redirectTo || '/developers/';
  }

  function isLoggedIn() {
    return !!getToken();
  }

  function isAdmin() {
    const id = getIdentity();
    return !!(id && id.is_admin === true);
  }

  /** The portal requires a PASSKEY-verified identity.
   *
   *  Not a taste decision. `user_id` is only stable when it derives from a
   *  stored credential; an e-mail-only sign-in mints a fresh one every session,
   *  so platform ownership and admin membership silently detach from the
   *  person. Passkey-only makes both survive by construction. The server
   *  enforces the same rule — this check only renders a helpful page
   *  instead of a bare 403.
   *
   *  Machines never come through here: /hhttps/machine/register is its own
   *  path with its own operator-e-mail confirmation. */
  const PORTAL_REQUIRED_METHOD = 'passkey';

  /** Verified methods of the current identity, tolerant of both shapes:
   *  the structured `verified_methods` array and the legacy CSV `method`. */
  function getMethods() {
    const id = getIdentity();
    if (!id) return [];
    if (Array.isArray(id.verified_methods)) return id.verified_methods;
    if (Array.isArray(id.verifiedMethods))  return id.verifiedMethods;
    if (typeof id.method === 'string') {
      return id.method.split(',').map(m => m.trim()).filter(Boolean);
    }
    return [];
  }

  function hasPasskey() {
    return getMethods().includes(PORTAL_REQUIRED_METHOD);
  }

  function getTrust() {
    const id = getIdentity();
    if (!id) return 0;
    const t = id.trustScore ?? id.trust_score;
    return typeof t === 'number' ? t : null;
  }

  /** True if this identity may use the portal. */
  function hasPortalAccess() {
    if (!isLoggedIn()) return false;
    return hasPasskey();
  }

  /** @deprecated v5 — the 'developer' role no longer exists. Kept as an alias so
   *  older cached pages don't break. Use hasPortalAccess(). */
  function isDeveloper() {
    return hasPortalAccess();
  }

  // ─── Sign-in via the universal consent page ────────────────────────────
  // Same flow every other client uses (ask.iamhmn.org, the WordPress plugin):
  //
  //   button → /hhttps/oauth/authorize  → consent page ("Erlauben / Ablehnen")
  //          → no identity? relogin() → hhttps.org/?returnTo=<consent>
  //          → sign in → back to consent → Erlauben → back here
  //
  // Public client, so PKCE is mandatory. The verifier lives in sessionStorage
  // for the duration of the round trip.
  const OAUTH_CLIENT_ID = 'hhttps-developer-portal';
  const OAUTH_REDIRECT  = window.location.origin + '/developers/dashboard.html';
  const SS_PKCE_KEY     = 'hhttps_portal_pkce';
  const SS_STATE_KEY    = 'hhttps_portal_state';
  const SS_RETURN_KEY   = 'hhttps_portal_return';

  function randomUrlSafe(bytes) {
    const a = new Uint8Array(bytes);
    (window.crypto || window.msCrypto).getRandomValues(a);
    return btoa(String.fromCharCode.apply(null, a))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  async function sha256Base64Url(input) {
    const data   = new TextEncoder().encode(input);
    const digest = await window.crypto.subtle.digest('SHA-256', data);
    return btoa(String.fromCharCode.apply(null, new Uint8Array(digest)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  /** Start the consent flow. Returns a promise that never resolves — the page
   *  navigates away. */
  async function startSignIn(returnTo) {
    const verifier = randomUrlSafe(32);
    const state    = randomUrlSafe(16);
    let challenge, method;
    try {
      challenge = await sha256Base64Url(verifier);
      method    = 'S256';
    } catch (_) {
      // No SubtleCrypto (insecure origin). Plain is still a valid PKCE method
      // and the authorize endpoint accepts it; on https this never happens.
      challenge = verifier;
      method    = 'plain';
    }
    try {
      sessionStorage.setItem(SS_PKCE_KEY,  verifier);
      sessionStorage.setItem(SS_STATE_KEY, state);
      sessionStorage.setItem(SS_RETURN_KEY, returnTo || window.location.href);
    } catch (_) {}

    const q = new URLSearchParams({
      response_type:         'code',
      client_id:             OAUTH_CLIENT_ID,
      redirect_uri:          OAUTH_REDIRECT,
      scope:                 'openid',
      state:                 state,
      code_challenge:        challenge,
      code_challenge_method: method
    });
    window.location.href = '/hhttps/oauth/authorize?' + q.toString();
    return new Promise(() => {});
  }

  /** Handle the return leg: verify state, strip the query, restore the page the
   *  user originally wanted. The authorization code itself is not exchanged —
   *  the portal shares an origin with the issuer and keeps using the issuer
   *  identity, because /hhttps/developers/* and `admins` key on the raw
   *  user_id, which an OAuth token deliberately never carries. */
  function completeSignIn() {
    let params;
    try { params = new URL(window.location.href).searchParams; } catch (_) { return; }
    const code  = params.get('code');
    const err   = params.get('error');
    if (!code && !err) return;

    const expected = (() => { try { return sessionStorage.getItem(SS_STATE_KEY); } catch (_) { return null; } })();
    const got      = params.get('state');
    const clean    = () => {
      try {
        sessionStorage.removeItem(SS_PKCE_KEY);
        sessionStorage.removeItem(SS_STATE_KEY);
      } catch (_) {}
      const u = new URL(window.location.href);
      ['code', 'state', 'error', 'error_description'].forEach(k => u.searchParams.delete(k));
      window.history.replaceState({}, document.title, u.pathname + u.search + u.hash);
    };

    if (err) { clean(); toast(params.get('error_description') || err, 'error'); return; }
    if (expected && got !== expected) { clean(); toast('State mismatch — sign-in aborted.', 'error'); return; }

    let back = null;
    try { back = sessionStorage.getItem(SS_RETURN_KEY); sessionStorage.removeItem(SS_RETURN_KEY); } catch (_) {}
    clean();
    if (back && back !== window.location.href) {
      const target = new URL(back, window.location.origin);
      if (target.origin === window.location.origin) { window.location.href = target.href; }
    }
  }

  async function whoami() {
    return api('GET', '/hhttps/whoami');
  }

  async function verifyAdmin() {
    const token = getToken();
    if (!token) return false;
    try {
      const res = await fetch('/hhttps/admin/stats', {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const ok = res.ok;
      const id = getIdentity();
      if (id) { id.is_admin = ok; setIdentity(id); }
      return ok;
    } catch (_) { return false; }
  }

  function requireAuth(redirectTo) {
    if (!isLoggedIn()) {
      startSignIn(redirectTo || window.location.href);
      return false;
    }
    return true;
  }

  /** Show a friendly gate page if the identity has no confirmed e-mail.
   *  Admins bypass the gate. Returns true if the user should proceed. */
  function requirePortalAccess() {
    if (!requireAuth()) return false;
    if (hasPortalAccess()) return true;
    if (isAdmin()) return true;          // admins always pass
    renderAccessGate();
    return false;
  }

  /** @deprecated v5 — alias for requirePortalAccess(). */
  function requireDeveloper() {
    return requirePortalAccess();
  }

  function renderAccessGate() {
    const main = document.querySelector('main') || document.body;
    main.innerHTML = `
      <div class="container-narrow" style="padding: 64px 24px;">
        <div class="card card-bracketed" style="padding: 40px;">
          <span class="eyebrow">⚠ ${t('gate.title')}</span>
          <h1 class="mt-2 mb-3" data-i18n="gate.title">${t('gate.title')}</h1>
          <p class="lede mb-6" data-i18n="gate.lead">${t('gate.lead')}</p>

          <div class="alert alert-info mb-6">
            <span class="alert-icon">&#9432;</span>
            <div>
              <strong data-i18n="gate.why">${t('gate.why')}</strong>
              <div class="text-sm mt-2 muted" data-i18n="gate.why.text">${t('gate.why.text')}</div>
            </div>
          </div>

          <p class="text-sm muted mb-4">
            <span data-i18n="gate.methods">${t('gate.methods')}</span>
            <code class="code-inline">${escapeHtml(getMethods().join(', ') || t('gate.methods.none'))}</code>
          </p>

          <h3 class="mb-3" data-i18n="gate.howto">${t('gate.howto')}</h3>
          <ol style="padding-left: 20px; line-height: 1.7; color: var(--text-muted); font-size: 14px;">
            <li class="mb-2" data-i18n="gate.step1">${t('gate.step1')}</li>
            <li class="mb-2" data-i18n="gate.step2">${t('gate.step2')}</li>
            <li class="mb-2" data-i18n="gate.step3">${t('gate.step3')}</li>
          </ol>

          <div class="flex gap-3 mt-6" style="flex-wrap: wrap;">
            <a href="#" class="btn btn-primary js-signin" data-i18n="gate.cta.signin">${t('gate.cta.signin')}</a>
            <a href="/developers/" class="btn btn-ghost" data-i18n="gate.cta.back">${t('gate.cta.back')}</a>
          </div>

          <p class="text-sm muted mt-6" data-i18n="gate.bot.note"
             style="padding-top:16px;border-top:1px solid var(--border);">${t('gate.bot.note')}</p>
        </div>
      </div>`;
    wireSignIn(main);
  }

  /** Every sign-in control goes through the consent page. Idempotent. */
  function wireSignIn(root) {
    (root || document).querySelectorAll('.js-signin').forEach((el) => {
      if (el.dataset.signinWired === '1') return;
      el.dataset.signinWired = '1';
      el.addEventListener('click', (e) => { e.preventDefault(); startSignIn(); });
    });
  }

  // ─── API client ────────────────────────────────────────────────────────
  async function api(method, path, body) {
    const headers = { 'Content-Type': 'application/json' };
    const token = getToken();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const opts = { method, headers };
    if (body !== undefined) opts.body = JSON.stringify(body);
    const res = await fetch(API_BASE + path, opts);
    const ct = res.headers.get('content-type') || '';
    const data = ct.includes('application/json') ? await res.json().catch(() => null) : await res.text();
    if (!res.ok) {
      const err = new Error((data && (data.message || data.error)) || res.statusText || 'Request failed');
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }

  const developers = {
    register:    (p)       => api('POST',   '/hhttps/developers/clients', p),
    platforms:   ()        => api('GET',    '/hhttps/developers/clients'),
    platform:    (id)      => api('GET',    `/hhttps/developers/clients/${id}`),
    update:      (id, p)   => api('PATCH',  `/hhttps/developers/clients/${id}`, p),
    remove:      (id)      => api('DELETE', `/hhttps/developers/clients/${id}`),
    dnsCheck:    (id)      => api('POST',   `/hhttps/developers/clients/${id}/dns-check`),
    submitReview:(id)      => api('POST',   `/hhttps/developers/clients/${id}/submit-review`),
    resendEmail: (id)      => api('POST',   `/hhttps/developers/clients/${id}/resend-email`),
    stats:       (id)      => api('GET',    `/hhttps/developers/clients/${id}/stats`),
  };

  const admin = {
    stats:    ()           => api('GET',  '/hhttps/admin/stats'),
    queue:    ()           => api('GET',  '/hhttps/admin/clients/pending'),
    platforms:()           => api('GET',  '/hhttps/admin/clients'),
    approve:  (id)         => api('POST', `/hhttps/admin/clients/${id}/approve`),
    reject:   (id, reason) => api('POST', `/hhttps/admin/clients/${id}/reject`,  { reason }),
    suspend:  (id, reason) => api('POST', `/hhttps/admin/clients/${id}/suspend`, { reason }),
  };

  // ─── UI helpers ────────────────────────────────────────────────────────
  function renderIdentityBadge(container) {
    if (!container) return;
    const id = getIdentity();
    const uid = getUid();
    if (!id || !isLoggedIn()) {
      container.innerHTML = `<a href="#" class="topnav-link js-signin">${escapeHtml(t('nav.signin'))}</a>`;
      const link = container.querySelector('.js-signin');
      if (link) link.addEventListener('click', (e) => { e.preventDefault(); startSignIn(); });
      return;
    }
    // Prefer the durable user id over the (possibly absent) legacy uid key.
    const short = (id.user_id || uid || '').slice(0, 8) || (id.role || 'user');
    const adminTag = id.is_admin ? ' · admin' : '';
    const role = id.roleIcon ? id.roleIcon + ' ' : '';
    container.innerHTML = `
      <span class="topnav-identity" title="${escapeHtml(id.user_id || uid || '')}">
        <span class="topnav-identity-dot"></span>
        <span>${role}${escapeHtml(short)}${adminTag}</span>
      </span>
      <a href="#" class="topnav-link js-signout" data-i18n="nav.signout">${escapeHtml(t('nav.signout'))}</a>`;
  }

  function escapeHtml(s) {
    if (s == null) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
                    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function toast(msg, type) {
    let host = document.getElementById('toast-host');
    if (!host) {
      host = document.createElement('div');
      host.id = 'toast-host';
      host.style.cssText = 'position:fixed;bottom:24px;right:24px;display:flex;flex-direction:column;gap:8px;z-index:200';
      document.body.appendChild(host);
    }
    const tEl = document.createElement('div');
    const color = type === 'error' ? 'var(--danger)' : type === 'success' ? 'var(--accent)' : 'var(--info)';
    tEl.style.cssText = `background:var(--bg-card);border:1px solid ${color};color:var(--text);padding:10px 14px;border-radius:2px;font-size:13px;max-width:340px;box-shadow:0 4px 12px rgba(0,0,0,0.4);transition:opacity .4s`;
    tEl.textContent = msg;
    host.appendChild(tEl);
    setTimeout(() => tEl.style.opacity = '0', 3500);
    setTimeout(() => tEl.remove(), 4000);
  }

  function copyToClipboard(text, btn) {
    navigator.clipboard.writeText(text).then(() => {
      if (btn) {
        const orig = btn.textContent;
        btn.textContent = 'copied';
        setTimeout(() => btn.textContent = orig, 1500);
      }
    });
  }

  function fmtDate(iso) {
    if (!iso) return '—';
    try {
      const d = new Date(iso);
      return d.toLocaleString(getLang() === 'en' ? 'en-GB' : 'de-DE',
        { dateStyle: 'short', timeStyle: 'short' });
    } catch (_) { return iso; }
  }

  /** Attach the handler to every sign-out control on the page: the one the
   *  badge renders (.js-signout) and the static #signout-btn that dashboard
   *  and admin still ship. Idempotent — the badge re-renders after the admin
   *  probe, so this runs more than once. */
  function wireSignOut() {
    const nodes = document.querySelectorAll('#signout-btn, .js-signout');
    nodes.forEach((el) => {
      if (el.dataset.signoutWired === '1') return;
      el.dataset.signoutWired = '1';
      el.addEventListener('click', (e) => {
        e.preventDefault();
        el.textContent = getLang() === 'de' ? 'Abmelden …' : 'Signing out …';
        signOut();
      });
    });
  }

  // ─── Nav wiring ────────────────────────────────────────────────────────
  function initNav() {
    completeSignIn();               // handle the ?code=… return from consent
    const slot = document.getElementById('identity-slot');
    if (slot) renderIdentityBadge(slot);

    const path = window.location.pathname.replace(/\/+$/, '');
    document.querySelectorAll('.topnav-link[data-path]').forEach((a) => {
      const p = a.getAttribute('data-path').replace(/\/+$/, '');
      if (path === p || path.startsWith(p + '/')) a.classList.add('active');
    });

    wireSignOut();
    wireSignIn();

    // Language toggle wiring
    setLang(getLang());
    document.querySelectorAll('.lang-toggle button').forEach(btn => {
      btn.addEventListener('click', () => setLang(btn.dataset.lang));
    });

    if (isLoggedIn()) {
      verifyAdmin().then(() => {
        if (slot) renderIdentityBadge(slot);
        wireSignOut();
        wireSignIn();
      });
    }
  }

  // ─── Expose ────────────────────────────────────────────────────────────
  window.HHTTPS = {
    auth: { getToken, getUid, getIdentity, setIdentity, clearAuth, signOut,
            isLoggedIn, isAdmin, verifyAdmin, whoami,
            startSignIn, completeSignIn,
            getTrust, getMethods, hasPasskey,
            hasPortalAccess, requireAuth, requirePortalAccess,
            PORTAL_REQUIRED_METHOD,
            // deprecated aliases (v4 compat)
            isDeveloper, requireDeveloper },
    api:  { developers, admin, raw: api },
    ui:   { renderIdentityBadge, toast, copyToClipboard, escapeHtml, fmtDate, initNav },
    i18n: { t, setLang, getLang, applyTranslations },
  };

  document.addEventListener('DOMContentLoaded', initNav);
})();
