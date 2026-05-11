/**
 * HHTTPS Extension — Background Service Worker (v1.2.0)
 *
 * Identity-first architecture:
 *   - Stores the user's HHTTPS identity (token + refresh token + role)
 *   - Auto-refreshes tokens 5 minutes before expiry via chrome.alarms
 *   - Supports multiple identities (different roles, e.g. citizen + developer)
 *   - Tracks per-tab page HHTTPS state (separate concern from identity)
 *   - Responds to popup queries about identity and current page
 */

// ─── Storage keys ────────────────────────────────────────────────────────────
const STORAGE_IDENTITIES = 'hhttps_identities';   // array of identity objects
const STORAGE_ACTIVE_ID  = 'hhttps_active_id';    // id of currently-active identity
const ISSUER_BASE        = 'https://hhttps.org';
const REFRESH_AHEAD_MS   = 5 * 60_000;            // refresh 5 min before expiry

// ─── Per-tab page state (for showing current page's HHTTPS support) ─────────
const tabState = new Map();

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading') {
    tabState.set(tabId, {
      status: 'unknown',
      url:    tab.url || ''
    });
    updateBadge(tabId);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => tabState.delete(tabId));

// ─── Message router ──────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Identity captured from hhttps.org page
  if (msg.type === 'IDENTITY_CAPTURED' && msg.identity) {
    storeIdentity(msg.identity)
      .then(() => {
        scheduleRefreshFor(msg.identity);
        updateAllBadges();
        sendResponse({ ok: true });
      })
      .catch((e) => sendResponse({ ok: false, error: e.message }));
    return true;
  }

  // Page state from any tab's content script
  if (msg.type === 'PAGE_STATE' && sender.tab?.id) {
    tabState.set(sender.tab.id, { ...msg.state, url: sender.tab.url });
    updateBadge(sender.tab.id);
    sendResponse({ ok: true });
    return;
  }

  // Popup asks: what's my identity?
  if (msg.type === 'GET_ACTIVE_IDENTITY') {
    getActiveIdentity()
      .then((id) => sendResponse({ identity: id }))
      .catch(() => sendResponse({ identity: null }));
    return true;
  }

  // Popup asks: all identities (for role-switch UI)
  if (msg.type === 'GET_ALL_IDENTITIES') {
    getAllIdentities()
      .then((arr) => sendResponse({ identities: arr }))
      .catch(() => sendResponse({ identities: [] }));
    return true;
  }

  // Popup: switch active identity
  if (msg.type === 'SET_ACTIVE_IDENTITY' && msg.id) {
    setActiveIdentity(msg.id)
      .then(() => { updateAllBadges(); sendResponse({ ok: true }); })
      .catch((e) => sendResponse({ ok: false, error: e.message }));
    return true;
  }

  // Popup: remove identity (logout)
  if (msg.type === 'REMOVE_IDENTITY' && msg.id) {
    removeIdentity(msg.id)
      .then(() => { updateAllBadges(); sendResponse({ ok: true }); })
      .catch((e) => sendResponse({ ok: false, error: e.message }));
    return true;
  }

  // Popup: get current page state
  if (msg.type === 'GET_TAB_STATE' && msg.tabId) {
    sendResponse(tabState.get(msg.tabId) || { status: 'none' });
    return;
  }

  // Popup: refresh now (manual)
  if (msg.type === 'REFRESH_NOW' && msg.id) {
    refreshIdentity(msg.id)
      .then((id) => sendResponse({ ok: true, identity: id }))
      .catch((e) => sendResponse({ ok: false, error: e.message }));
    return true;
  }

  // Popup: revoke current token at server
  if (msg.type === 'REVOKE_IDENTITY' && msg.id) {
    revokeAndRemove(msg.id)
      .then(() => { updateAllBadges(); sendResponse({ ok: true }); })
      .catch((e) => sendResponse({ ok: false, error: e.message }));
    return true;
  }
});

// ─── Identity storage primitives ─────────────────────────────────────────────
async function getAllIdentities() {
  const r = await chrome.storage.local.get([STORAGE_IDENTITIES]);
  return r[STORAGE_IDENTITIES] || [];
}

async function getActiveIdentity() {
  const r = await chrome.storage.local.get([STORAGE_IDENTITIES, STORAGE_ACTIVE_ID]);
  const list = r[STORAGE_IDENTITIES] || [];
  if (list.length === 0) return null;
  const activeId = r[STORAGE_ACTIVE_ID];
  if (activeId) {
    const found = list.find(i => i.id === activeId);
    if (found) return found;
  }
  return list[0];   // fall back to first
}

async function storeIdentity(rawIdentity) {
  const list = await getAllIdentities();
  const id = computeIdentityId(rawIdentity);
  const enriched = { ...rawIdentity, id, capturedAt: Date.now() };
  // Replace existing entry with same id (re-issuance) or push new
  const idx = list.findIndex(i => i.id === id);
  if (idx >= 0) list[idx] = enriched;
  else list.push(enriched);

  await chrome.storage.local.set({
    [STORAGE_IDENTITIES]: list,
    [STORAGE_ACTIVE_ID]:  id
  });
}

async function setActiveIdentity(id) {
  await chrome.storage.local.set({ [STORAGE_ACTIVE_ID]: id });
}

async function removeIdentity(id) {
  const list = await getAllIdentities();
  const filtered = list.filter(i => i.id !== id);
  await chrome.storage.local.set({ [STORAGE_IDENTITIES]: filtered });
  const r = await chrome.storage.local.get([STORAGE_ACTIVE_ID]);
  if (r[STORAGE_ACTIVE_ID] === id) {
    await chrome.storage.local.set({
      [STORAGE_ACTIVE_ID]: filtered[0]?.id || null
    });
  }
}

function computeIdentityId(identity) {
  // Stable id = issuer + role  → switching roles produces different ids,
  // re-issuing same role overwrites the previous entry
  const issuer = identity.issuer || 'hhttps://hhttps.org';
  const role   = identity.role || 'unknown';
  return `${issuer}#${role}`;
}

// ─── Auto-refresh ────────────────────────────────────────────────────────────
async function scheduleRefreshFor(identity) {
  if (!identity?.refreshToken) return;
  try {
    const payload = decodeJwtPayload(identity.token);
    if (!payload?.exp) return;
    const expMs   = payload.exp * 1000;
    const fireAt  = expMs - REFRESH_AHEAD_MS;
    const alarmName = `refresh_${identity.id}`;
    if (fireAt <= Date.now() + 1000) {
      refreshIdentity(identity.id).catch(() => {});
      return;
    }
    chrome.alarms.create(alarmName, { when: fireAt });
  } catch (e) {}
}

chrome.alarms?.onAlarm.addListener((alarm) => {
  if (alarm.name.startsWith('refresh_')) {
    const id = alarm.name.replace(/^refresh_/, '');
    refreshIdentity(id).catch(() => {});
  }
});

async function refreshIdentity(id) {
  const list = await getAllIdentities();
  const idx  = list.findIndex(i => i.id === id);
  if (idx < 0) throw new Error('identity not found');
  const ident = list[idx];
  if (!ident.refreshToken) throw new Error('no refresh token');

  const issuerBase = (ident.issuer || ISSUER_BASE).replace(/^hhttps:\/\//, 'https://').replace(/\/$/, '');
  const res = await fetch(`${issuerBase}/hhttps/token/refresh`, {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ refreshToken: ident.refreshToken })
  });
  if (!res.ok) {
    const errBody = await res.json().catch(() => ({}));
    throw new Error(errBody.error || `refresh failed: ${res.status}`);
  }
  const data = await res.json();
  if (!data.token) throw new Error('no token in refresh response');

  // Update identity with new tokens
  list[idx] = {
    ...ident,
    token:            data.token,
    refreshToken:     data.refreshToken || ident.refreshToken,
    trustScore:       data.role?.trustScore || ident.trustScore,
    expiresAt:        data.expiresAt || null,
    refreshExpiresAt: data.refreshExpiresAt || ident.refreshExpiresAt,
    lastRefreshAt:    Date.now()
  };
  await chrome.storage.local.set({ [STORAGE_IDENTITIES]: list });
  scheduleRefreshFor(list[idx]);
  return list[idx];
}

async function revokeAndRemove(id) {
  const list = await getAllIdentities();
  const ident = list.find(i => i.id === id);
  if (!ident) return;

  const issuerBase = (ident.issuer || ISSUER_BASE).replace(/^hhttps:\/\//, 'https://').replace(/\/$/, '');
  try {
    await fetch(`${issuerBase}/hhttps/revoke`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ token: ident.token })
    });
  } catch (e) {
    // Server unreachable — still remove locally
  }
  await removeIdentity(id);
}

// ─── Badge logic ─────────────────────────────────────────────────────────────
async function updateAllBadges() {
  const tabs = await chrome.tabs.query({});
  for (const t of tabs) {
    if (t.id) updateBadge(t.id);
  }
}

async function updateBadge(tabId) {
  const ident = await getActiveIdentity();
  let text, color, title;

  if (ident) {
    // Show seal: verified user always sees their badge
    text  = '✓';
    color = '#5BAF6B';
    const roleLabel = ident.roleLabel || ident.role || 'verified';
    title = `HHTTPS · ${ident.roleIcon || '👤'} ${roleLabel} · Trust ${ident.trustScore || 0}/100`;
  } else {
    text  = '';
    color = '#7A6F62';
    title = 'HHTTPS — Nicht eingeloggt. Klick zum Verifizieren.';
  }

  try {
    chrome.action.setBadgeText({ tabId, text });
    chrome.action.setBadgeBackgroundColor({ tabId, color });
    chrome.action.setTitle({ tabId, title });
  } catch (e) {}
}

// ─── Utilities ───────────────────────────────────────────────────────────────
function decodeJwtPayload(token) {
  try {
    const p = token.split('.')[1];
    const padded = p + '='.repeat((4 - p.length % 4) % 4);
    return JSON.parse(atob(padded.replace(/-/g, '+').replace(/_/g, '/')));
  } catch (e) {
    return null;
  }
}

// ─── Lifecycle: rebuild refresh schedule on startup ──────────────────────────
chrome.runtime.onStartup?.addListener(rebuildSchedules);
chrome.runtime.onInstalled?.addListener(rebuildSchedules);

async function rebuildSchedules() {
  const list = await getAllIdentities();
  for (const ident of list) scheduleRefreshFor(ident);
  updateAllBadges();
}

// Initial badge setup when service worker wakes
updateAllBadges();
