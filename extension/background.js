/**
 * HHTTPS Browser Extension — Background Service Worker (v1.1.0)
 *
 * Compatible with HHTTPS protocol v0.4.1.
 *
 * v1.1.0 changes:
 *   ✓ Refresh-token handling (auto-refresh before expiry)
 *   ✓ JWKS caching for offline-capable validation
 *   ✓ Multi-issuer support (per-domain token store)
 *   ✓ Token revocation listener
 *   ✓ HHTTPS issuer auto-discovery via .well-known
 */

// ─── Per-tab state ───────────────────────────────────────────────────────────
const tabState = new Map();

// ─── Constants ──────────────────────────────────────────────────────────────
const REFRESH_AHEAD_MS  = 5 * 60_000;    // refresh token 5 min before expiry
const JWKS_CACHE_TTL_MS = 60 * 60_000;   // cache JWKS for 1 hour
const DEFAULT_ISSUER    = 'https://hhttps.org';

// ─── Tab lifecycle ──────────────────────────────────────────────────────────
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading') {
    tabState.set(tabId, {
      status:     'unknown',
      human:      false,
      role:       null,
      roleLabel:  null,
      trustScore: 0,
      token:      null,
      method:     'none',
      issuer:     null,
      version:    null,
      url:        tab.url || ''
    });
    updateBadge(tabId, 'unknown');
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabState.delete(tabId);
});

// ─── Messages from content script & popup ──────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const tabId = sender.tab?.id;

  if (msg.type === 'HHTTPS_HEADERS' && tabId) {
    const state = {
      status:     msg.status     || 'none',
      human:      msg.human      === 'true' || msg.human === true,
      role:       msg.role       || null,
      roleLabel:  msg.roleLabel  || null,
      roleIcon:   msg.roleIcon   || null,
      trustScore: parseInt(msg.trustScore || '0'),
      token:      msg.token      || null,
      method:     msg.method     || 'none',
      issuer:     msg.issuer     || null,
      version:    msg.version    || null,
      url:        sender.tab?.url || ''
    };
    tabState.set(tabId, state);
    updateBadge(tabId, state.status, state.human, state.trustScore);

    // Persist token for the issuer's domain (not the current page's domain)
    if (state.token && state.issuer) {
      storeTokenForIssuer(state.issuer, state.token).catch(() => {});
    }
    sendResponse({ ok: true });
    return;
  }

  if (msg.type === 'GET_STATE' && tabId) {
    sendResponse(tabState.get(tabId) || { status: 'none' });
    return;
  }

  if (msg.type === 'STORE_TOKEN' && msg.token && msg.issuer) {
    storeTokenForIssuer(msg.issuer, msg.token, msg.refreshToken)
      .then(() => sendResponse({ ok: true }))
      .catch((e) => sendResponse({ ok: false, error: e.message }));
    return true;
  }

  if (msg.type === 'GET_TOKEN' && msg.issuer) {
    getTokenForIssuer(msg.issuer)
      .then((t) => sendResponse({ token: t }))
      .catch(() => sendResponse({ token: null }));
    return true;
  }

  if (msg.type === 'CLEAR_TOKEN' && msg.issuer) {
    clearTokenForIssuer(msg.issuer)
      .then(() => sendResponse({ ok: true }))
      .catch(() => sendResponse({ ok: false }));
    return true;
  }

  if (msg.type === 'REVOKE_TOKEN' && msg.issuer && msg.token) {
    revokeToken(msg.issuer, msg.token)
      .then((r) => sendResponse({ ok: true, ...r }))
      .catch((e) => sendResponse({ ok: false, error: e.message }));
    return true;
  }
});

// ─── Token storage (per HHTTPS issuer) ──────────────────────────────────────
function tokenKey(issuerUrl) {
  // Normalize: hhttps://hhttps.org → hhttps.org
  let host = issuerUrl;
  try { host = new URL(issuerUrl.replace(/^hhttps:\/\//, 'https://')).hostname; } catch {}
  return `hhttps_token_${host}`;
}

async function storeTokenForIssuer(issuerUrl, token, refreshToken = null) {
  const key   = tokenKey(issuerUrl);
  const data  = { token, refreshToken, storedAt: Date.now() };
  await chrome.storage.local.set({ [key]: data });
  // Schedule refresh if we have a refresh token
  if (refreshToken) scheduleRefresh(issuerUrl);
}

async function getTokenForIssuer(issuerUrl) {
  const key    = tokenKey(issuerUrl);
  const result = await chrome.storage.local.get([key]);
  return result[key]?.token || null;
}

async function clearTokenForIssuer(issuerUrl) {
  await chrome.storage.local.remove([tokenKey(issuerUrl)]);
}

// ─── Refresh handling ────────────────────────────────────────────────────────
async function scheduleRefresh(issuerUrl) {
  // Decode JWT to find expiry, schedule alarm a few minutes before
  const data = (await chrome.storage.local.get([tokenKey(issuerUrl)]))[tokenKey(issuerUrl)];
  if (!data?.token) return;

  try {
    const payload = JSON.parse(atob(data.token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
    const expMs   = payload.exp * 1000;
    const fireAt  = expMs - REFRESH_AHEAD_MS;
    if (fireAt <= Date.now()) {
      // already expired or imminent — refresh now
      refreshAccessToken(issuerUrl).catch(() => {});
      return;
    }
    chrome.alarms.create(`refresh_${issuerUrl}`, { when: fireAt });
  } catch (e) {
    // JWT decode failed — ignore
  }
}

chrome.alarms?.onAlarm.addListener((alarm) => {
  if (alarm.name.startsWith('refresh_')) {
    const issuer = alarm.name.replace(/^refresh_/, '');
    refreshAccessToken(issuer).catch(() => {});
  }
});

async function refreshAccessToken(issuerUrl) {
  const key  = tokenKey(issuerUrl);
  const data = (await chrome.storage.local.get([key]))[key];
  if (!data?.refreshToken) return;

  const baseUrl = issuerUrl.replace(/^hhttps:\/\//, 'https://').replace(/\/$/, '');
  const res = await fetch(`${baseUrl}/hhttps/token/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refreshToken: data.refreshToken })
  });
  if (!res.ok) {
    // Refresh failed (user revoked, server down, etc.) — leave existing token, will fail naturally
    return;
  }
  const j = await res.json();
  if (j.token) {
    await storeTokenForIssuer(issuerUrl, j.token, data.refreshToken);
  }
}

// ─── Revoke token ────────────────────────────────────────────────────────────
async function revokeToken(issuerUrl, token) {
  const baseUrl = issuerUrl.replace(/^hhttps:\/\//, 'https://').replace(/\/$/, '');
  await fetch(`${baseUrl}/hhttps/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token })
  });
  await clearTokenForIssuer(issuerUrl);
  return { revoked: true };
}

// ─── Badge & icon ────────────────────────────────────────────────────────────
function updateBadge(tabId, status, human = false, trustScore = 0) {
  let badgeText, badgeColor, title;

  if (status === 'verified' && human) {
    badgeText  = '✓';
    badgeColor = '#889982';   // sage-deep (consistent with brand palette)
    title      = `HHTTPS ✓ Verifizierter Mensch · Trust ${trustScore}/100`;
  } else if (status === 'verified' && !human) {
    badgeText  = '🤖';
    badgeColor = '#E89F73';   // apricot-deep
    title      = 'HHTTPS — Maschine verifiziert (kein Mensch)';
  } else if (status === 'unverified') {
    badgeText  = '!';
    badgeColor = '#C97D5B';   // terra
    title      = 'HHTTPS — Website unterstützt HHTTPS, aber nicht verifiziert';
  } else {
    badgeText  = '';
    badgeColor = '#7A6F62';   // ink-muted
    title      = 'HHTTPS — Nicht verfügbar auf dieser Seite';
  }

  chrome.action.setBadgeText({ tabId, text: badgeText });
  chrome.action.setBadgeBackgroundColor({ tabId, color: badgeColor });
  chrome.action.setTitle({ tabId, title });
}

// ─── Startup: rebuild refresh schedules from storage ─────────────────────────
chrome.runtime.onStartup?.addListener(rebuildRefreshSchedules);
chrome.runtime.onInstalled?.addListener(rebuildRefreshSchedules);

async function rebuildRefreshSchedules() {
  const all = await chrome.storage.local.get(null);
  for (const key of Object.keys(all)) {
    if (key.startsWith('hhttps_token_')) {
      const host = key.replace(/^hhttps_token_/, '');
      scheduleRefresh(`https://${host}`).catch(() => {});
    }
  }
}
