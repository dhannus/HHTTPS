/* ============================================================
   HHTTPS Developer Portal — Shared JS  (v4 — i18n + role-gate + resend)
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
      // role gate
      'gate.title':         'Developer-Rolle erforderlich',
      'gate.lead':          'Das Developer Dashboard ist nur mit der Rolle "developer" zugänglich. Aktuell bist du als "{role}" angemeldet.',
      'gate.howto':         'So bekommst du Zugang',
      'gate.step1':         'Gehe zu hhttps.org und logge dich aus, falls du eingeloggt bist.',
      'gate.step2':         'Bei der erneuten Verifikation wähle die Rolle "💻 Entwickler" (Developer).',
      'gate.step3':         'Bestätige eine E-Mail-Domain, die mit Entwicklung zu tun hat (Firmen-Domain, GitHub-verbundene Adresse o. ä.).',
      'gate.cta.signin':    'Zu hhttps.org →',
      'gate.cta.back':      '← Zurück zur Übersicht',
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
      'gate.title':         'Developer role required',
      'gate.lead':          'The developer dashboard is only accessible with the "developer" role. You are currently signed in as "{role}".',
      'gate.howto':         'How to get access',
      'gate.step1':         'Go to hhttps.org and sign out if you are signed in.',
      'gate.step2':         'When re-verifying, pick the role "💻 Entwickler" (Developer).',
      'gate.step3':         'Confirm an email at a domain related to your development work.',
      'gate.cta.signin':    'Go to hhttps.org →',
      'gate.cta.back':      '← Back to overview',
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

  function isLoggedIn() {
    return !!getToken();
  }

  function isAdmin() {
    const id = getIdentity();
    return !!(id && id.is_admin === true);
  }

  function isDeveloper() {
    const id = getIdentity();
    return !!(id && id.role === 'developer');
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
      window.location.href = redirectTo || '/';
      return false;
    }
    return true;
  }

  /** Show a friendly role-gate page if the user isn't a developer.
   *  Admins bypass the gate. Returns true if the user should proceed. */
  function requireDeveloper() {
    if (!requireAuth()) return false;
    if (isDeveloper()) return true;
    // Admins can pass too
    if (isAdmin()) return true;
    renderRoleGate();
    return false;
  }

  function renderRoleGate() {
    const id = getIdentity() || {};
    const role = id.role || 'unknown';
    const main = document.querySelector('main') || document.body;
    main.innerHTML = `
      <div class="container-narrow" style="padding: 64px 24px;">
        <div class="card card-bracketed" style="padding: 40px;">
          <span class="eyebrow">⚠ ${t('gate.title')}</span>
          <h1 class="mt-2 mb-3" data-i18n="gate.title">${t('gate.title')}</h1>
          <p class="lede mb-6">${t('gate.lead', { role: escapeHtml(role) })}</p>

          <h3 class="mb-3" data-i18n="gate.howto">${t('gate.howto')}</h3>
          <ol style="padding-left: 20px; line-height: 1.7; color: var(--text-muted); font-size: 14px;">
            <li class="mb-2" data-i18n="gate.step1">${t('gate.step1')}</li>
            <li class="mb-2" data-i18n="gate.step2">${t('gate.step2')}</li>
            <li class="mb-2" data-i18n="gate.step3">${t('gate.step3')}</li>
          </ol>

          <div class="flex gap-3 mt-6" style="flex-wrap: wrap;">
            <a href="/" class="btn btn-primary" data-i18n="gate.cta.signin">${t('gate.cta.signin')}</a>
            <a href="/developers/" class="btn btn-ghost" data-i18n="gate.cta.back">${t('gate.cta.back')}</a>
          </div>
        </div>
      </div>`;
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
      container.innerHTML = `<a href="/" class="topnav-link">${escapeHtml(t('nav.signin'))}</a>`;
      return;
    }
    const short = uid ? uid.slice(0, 8) : (id.role || 'user');
    const adminTag = id.is_admin ? ' · admin' : '';
    const role = id.roleIcon ? id.roleIcon + ' ' : '';
    container.innerHTML = `
      <span class="topnav-identity">
        <span class="topnav-identity-dot"></span>
        <span>${role}${escapeHtml(short)}${adminTag}</span>
      </span>`;
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

  // ─── Nav wiring ────────────────────────────────────────────────────────
  function initNav() {
    const slot = document.getElementById('identity-slot');
    if (slot) renderIdentityBadge(slot);

    const path = window.location.pathname.replace(/\/+$/, '');
    document.querySelectorAll('.topnav-link[data-path]').forEach((a) => {
      const p = a.getAttribute('data-path').replace(/\/+$/, '');
      if (path === p || path.startsWith(p + '/')) a.classList.add('active');
    });

    const out = document.getElementById('signout-btn');
    if (out) out.addEventListener('click', (e) => {
      e.preventDefault();
      clearAuth();
      window.location.href = '/';
    });

    // Language toggle wiring
    setLang(getLang());
    document.querySelectorAll('.lang-toggle button').forEach(btn => {
      btn.addEventListener('click', () => setLang(btn.dataset.lang));
    });

    if (isLoggedIn()) {
      verifyAdmin().then(() => {
        if (slot) renderIdentityBadge(slot);
      });
    }
  }

  // ─── Expose ────────────────────────────────────────────────────────────
  window.HHTTPS = {
    auth: { getToken, getUid, getIdentity, setIdentity, clearAuth,
            isLoggedIn, isAdmin, isDeveloper, verifyAdmin,
            requireAuth, requireDeveloper },
    api:  { developers, admin, raw: api },
    ui:   { renderIdentityBadge, toast, copyToClipboard, escapeHtml, fmtDate, initNav },
    i18n: { t, setLang, getLang, applyTranslations },
  };

  document.addEventListener('DOMContentLoaded', initNav);
})();
