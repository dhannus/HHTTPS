/**
 * HHTTPS Extension Popup v1.2.0
 *
 * Identity-first: show the user's verified identity prominently,
 * page state secondarily. Provides actions: refresh, copy token,
 * logout, switch role, copy signature snippet.
 */

// ─── DOM refs ───────────────────────────────────────────────────────────────
const el = (id) => document.getElementById(id);
const hero          = el('identityHero');
const identityIcon  = el('identityIcon');
const identityStatus= el('identityStatus');
const identityRole  = el('identityRole');
const identityLevel = el('identityLevel');
const trustWrap     = el('trustWrap');
const trustValue    = el('trustValue');
const trustFill     = el('trustFill');
const expiry        = el('expiry');
const emptyState    = el('emptyState');
const idActions     = el('idActions');
const roleSwitch    = el('roleSwitch');
const snippetSec    = el('snippet');
const snippetBox    = el('snippetBox');
const pageRow       = el('pageRow');
const pageLabel     = el('pageLabel');
const pageUrl       = el('pageUrl');

// ─── Initial state ──────────────────────────────────────────────────────────
function applyStaticI18n(root = document) {
  root.querySelectorAll('[data-i18n]').forEach(e => { const m = chrome.i18n.getMessage(e.dataset.i18n); if (m) e.textContent = m; });
  root.querySelectorAll('[data-i18n-title]').forEach(e => { const m = chrome.i18n.getMessage(e.dataset.i18nTitle); if (m) e.title = m; });
  try { document.documentElement.lang = chrome.i18n.getUILanguage().split('-')[0]; } catch (e) {}
}

async function init() {
  applyStaticI18n();
  // Load identity
  const idResp = await sendMsg({ type: 'GET_ACTIVE_IDENTITY' });
  const ident = idResp?.identity;

  if (ident) {
    renderIdentity(ident);
    await renderRoleSwitcher(ident);
  } else {
    renderEmptyState();
  }

  // Load current page info
  await renderPageState();

  // Wire up actions
  el('refreshBtn').addEventListener('click', () => doRefresh(ident));
  el('copyTokenBtn').addEventListener('click', () => doCopyToken(ident));
  el('logoutBtn').addEventListener('click', () => doLogout(ident));
  el('copySnippetBtn').addEventListener('click', () => doCopySnippet(ident));

  // Sign-mode preference: load current, persist on change
  await initSignModeSwitch();
}

async function initSignModeSwitch() {
  const resp = await sendMsg({ type: 'GET_SIGN_MODE' });
  const current = resp?.mode || 'alpha';
  const radios = document.querySelectorAll('input[name="signmode"]');
  radios.forEach(r => {
    r.checked = (r.value === current);
    r.addEventListener('change', async () => {
      if (r.checked) {
        await sendMsg({ type: 'SET_SIGN_MODE', mode: r.value });
      }
    });
  });
}

// ─── Render identity (verified) ─────────────────────────────────────────────
function renderIdentity(ident) {
  hero.classList.remove('empty');
  hero.classList.add('verified');
  emptyState.classList.remove('show');
  idActions.classList.add('show');

  identityIcon.textContent  = ident.roleIcon || '👤';
  identityStatus.textContent = chrome.i18n.getMessage('verifiedStatus');
  identityRole.textContent  = ident.roleLabel || ident.role || 'Verified';
  identityLevel.textContent = ident.levelLabel
    ? `via ${ident.levelLabel}`
    : (ident.roleLevel ? `via ${ident.roleLevel}` : 'WebAuthn');

  const score = ident.trustScore || 0;
  trustWrap.classList.add('show');
  trustValue.textContent = `${score} / 100`;
  requestAnimationFrame(() => { trustFill.style.width = score + '%'; });

  // Expiry countdown
  renderExpiry(ident);

  // Signature snippet
  renderSignatureSnippet(ident);
}

function renderEmptyState() {
  hero.classList.remove('verified');
  hero.classList.add('empty');
  emptyState.classList.add('show');
  idActions.classList.remove('show');
  snippetSec.classList.remove('show');
  roleSwitch.classList.remove('show');

  identityIcon.textContent  = '🔒';
  identityStatus.textContent = chrome.i18n.getMessage('identityStatusLoggedOut');
  identityRole.textContent  = chrome.i18n.getMessage('identityNoIdentity');
  identityLevel.textContent = chrome.i18n.getMessage('loginAtHhttpsLong');
  trustWrap.classList.remove('show');
  expiry.textContent = '';
}

function renderExpiry(ident) {
  if (!ident.expiresAt) {
    expiry.textContent = '';
    return;
  }
  const now = Date.now();
  const exp = new Date(ident.expiresAt).getTime();
  const minLeft = Math.floor((exp - now) / 60_000);

  if (minLeft <= 0) {
    expiry.textContent = chrome.i18n.getMessage('tokenExpiredRefreshing');
    expiry.classList.add('warning');
  } else if (minLeft < 10) {
    expiry.textContent = chrome.i18n.getMessage('tokenExpiresInMin', [String(minLeft)]);
    expiry.classList.add('warning');
  } else if (minLeft < 60) {
    expiry.textContent = chrome.i18n.getMessage('tokenValidMinLeft', [String(minLeft)]);
    expiry.classList.remove('warning');
  } else {
    expiry.textContent = chrome.i18n.getMessage('tokenValidHm', [String(Math.floor(minLeft / 60)), String(minLeft % 60)]);
    expiry.classList.remove('warning');
  }
}

// ─── Role switcher (only if multiple identities) ────────────────────────────
async function renderRoleSwitcher(activeIdent) {
  const r = await sendMsg({ type: 'GET_ALL_IDENTITIES' });
  const all = r?.identities || [];
  if (all.length < 2) {
    roleSwitch.classList.remove('show');
    return;
  }

  // Clear and rebuild chips
  roleSwitch.querySelectorAll('.role-chip').forEach(c => c.remove());
  all.forEach(ident => {
    const chip = document.createElement('button');
    chip.className = 'role-chip' + (ident.id === activeIdent.id ? ' active' : '');
    chip.innerHTML = `<span>${ident.roleIcon || '👤'}</span><span>${ident.roleLabel || ident.role}</span>`;
    chip.addEventListener('click', async () => {
      await sendMsg({ type: 'SET_ACTIVE_IDENTITY', id: ident.id });
      window.location.reload();
    });
    roleSwitch.appendChild(chip);
  });
  roleSwitch.classList.add('show');
}

// ─── Signature snippet ──────────────────────────────────────────────────────
function renderSignatureSnippet(ident) {
  // Compact snippet that can be pasted into any text field as a portable
  // identity claim. Phase 2 will turn this into invisible markers via
  // zero-width characters, but for now the visible form is useful.
  const snip = buildSnippet(ident);
  snippetBox.textContent = snip;
  snippetSec.classList.add('show');
}

function buildSnippet(ident) {
  // Format: [HHTTPS verified · role · trust · jti-shortened]
  // Plus the full token at the end (for verification)
  const role   = ident.role || 'human';
  const trust  = ident.trustScore || 60;
  const icon   = ident.roleIcon || '👤';
  const label  = ident.roleLabel || ident.role || chrome.i18n.getMessage('roleFallback');
  return `[HHTTPS ✓ ${icon} ${label} · Trust ${trust}/100 · ${ident.token}]`;
}

// ─── Page state ─────────────────────────────────────────────────────────────
async function renderPageState() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab) return;

  // Show URL hostname
  try {
    const u = new URL(tab.url);
    pageUrl.textContent = u.hostname;
  } catch (e) {
    pageUrl.textContent = tab.url || '';
  }

  // Special case: hhttps.org → "Identity issuer"
  try {
    const host = new URL(tab.url).hostname;
    if (host === 'hhttps.org' || host === 'www.hhttps.org') {
      pageRow.querySelector('.page-icon').textContent = '🏛️';
      pageLabel.textContent = 'HHTTPS Identity Provider';
      return;
    }
  } catch (e) {}

  // Try to query content script
  let state = null;
  try {
    state = await new Promise((resolve) => {
      const timer = setTimeout(() => resolve(null), 600);
      chrome.tabs.sendMessage(tab.id, { type: 'GET_PAGE_STATE' }, (resp) => {
        clearTimeout(timer);
        if (chrome.runtime.lastError) return resolve(null);
        resolve(resp);
      });
    });
  } catch (e) {}

  if (state && state.status && state.status !== 'none' && state.status !== 'unknown') {
    pageRow.querySelector('.page-icon').textContent =
      state.human ? '✓' : (state.status === 'unverified' ? '!' : '?');
    pageLabel.textContent = state.status === 'verified'
      ? chrome.i18n.getMessage('pageHhttpsActive', [state.role || chrome.i18n.getMessage('verifiedFallback')])
      : chrome.i18n.getMessage('pageSupportedNotVerified');
  } else {
    pageRow.querySelector('.page-icon').textContent = '○';
    pageLabel.textContent = chrome.i18n.getMessage('pageNotSupported');
  }
}

// ─── Actions ────────────────────────────────────────────────────────────────
async function doRefresh(ident) {
  if (!ident) return;
  const btn = el('refreshBtn');
  btn.disabled = true;
  btn.innerHTML = '<span>↻</span> <span>...</span>';

  const r = await sendMsg({ type: 'REFRESH_NOW', id: ident.id });
  if (r?.ok && r.identity) {
    renderIdentity(r.identity);
    btn.innerHTML = `<span>✓</span> <span>${chrome.i18n.getMessage('updatedLabel')}</span>`;
    setTimeout(() => {
      btn.innerHTML = `<span>↻</span> <span>${chrome.i18n.getMessage('refreshLabel')}</span>`;
      btn.disabled = false;
    }, 1500);
  } else {
    btn.innerHTML = `<span>✗</span> <span>${chrome.i18n.getMessage('errorLabel')}</span>`;
    setTimeout(() => {
      btn.innerHTML = `<span>↻</span> <span>${chrome.i18n.getMessage('refreshLabel')}</span>`;
      btn.disabled = false;
    }, 2000);
  }
}

async function doCopyToken(ident) {
  if (!ident?.token) return;
  const btn = el('copyTokenBtn');
  try {
    await navigator.clipboard.writeText(ident.token);
    btn.innerHTML = `<span>✓</span> <span>${chrome.i18n.getMessage('copiedLabel')}</span>`;
    setTimeout(() => {
      btn.innerHTML = `<span>⎘</span> <span>${chrome.i18n.getMessage('tokenLabel')}</span>`;
    }, 1500);
  } catch (e) {
    btn.innerHTML = `<span>✗</span> <span>${chrome.i18n.getMessage('errorLabel')}</span>`;
    setTimeout(() => {
      btn.innerHTML = `<span>⎘</span> <span>${chrome.i18n.getMessage('tokenLabel')}</span>`;
    }, 2000);
  }
}

async function doCopySnippet(ident) {
  if (!ident) return;
  const btn = el('copySnippetBtn');
  try {
    await navigator.clipboard.writeText(buildSnippet(ident));
    btn.textContent = chrome.i18n.getMessage('copiedCheck');
    btn.classList.add('copied');
    setTimeout(() => {
      btn.textContent = chrome.i18n.getMessage('copyToClipboard');
      btn.classList.remove('copied');
    }, 1500);
  } catch (e) {
    btn.textContent = chrome.i18n.getMessage('copyBlocked');
    setTimeout(() => {
      btn.textContent = chrome.i18n.getMessage('copyToClipboard');
    }, 2500);
  }
}

async function doLogout(ident) {
  if (!ident) return;
  const confirmed = confirm(chrome.i18n.getMessage('logoutConfirm'));
  if (!confirmed) return;

  const r = await sendMsg({ type: 'REVOKE_IDENTITY', id: ident.id });
  if (r?.ok) {
    window.location.reload();
  } else {
    alert(chrome.i18n.getMessage('logoutFailed', [r?.error || chrome.i18n.getMessage('unknownError')]));
  }
}

// ─── Helper ─────────────────────────────────────────────────────────────────
function sendMsg(msg) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(msg, (resp) => {
        if (chrome.runtime.lastError) return resolve(null);
        resolve(resp);
      });
    } catch (e) {
      resolve(null);
    }
  });
}

document.addEventListener('DOMContentLoaded', init);
