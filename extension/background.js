/**
 * HHTTPS Extension — Background Service Worker
 *
 * AP8-48 (#249): the version is NOT repeated here. `chrome.runtime.getManifest()
 * .version` is the single source; manifest.json is the only place it is written.
 *
 * Identity-first architecture:
 *   - Stores the user's HHTTPS identity (token + refresh token + role)
 *   - Auto-refreshes tokens 5 minutes before expiry via chrome.alarms
 *   - Supports multiple identities (different roles, e.g. citizen + developer)
 *   - Responds to popup queries about the identity
 *   - Signs selected text through the context menu
 *
 * AP8-45 (#240): the per-tab page-state cache, the message that fed it and
 * the query that read it back were removed — nothing ever read them, because
 * the popup asks the tab directly (GET_PAGE_STATE). The unused logout
 * message went with them: the popup revokes instead of just removing.
 * AP8-53 (#249): ONE message router instead of three listeners, and the issuer
 * base comes from lib/identity.js instead of six inline replace() calls.
 */

import {
  ISSUER_BASE, STORAGE_IDENTITIES, STORAGE_ACTIVE_ID, STORAGE_SIGN_MODE,
  issuerBase, computeIdentityId, refreshFireAt,
  alarmNameFor, idFromAlarmName, normaliseSignMode, bindingTypeFor, applyRefresh
} from './lib/identity.js';

// ─── Message router ──────────────────────────────────────────────────────────
// Every handler returns either undefined (answered synchronously) or a promise
// (the router then keeps the message channel open and answers with its value).
const HANDLERS = {
  // Identity captured from the hhttps.org page.
  IDENTITY_CAPTURED: (msg) => {
    if (!msg.identity) return { ok: false, error: 'no identity' };
    // AP8-04 (#72): schedule the refresh for the STORED identity — only that
    // one carries the `id` the alarm name and refreshIdentity() need. The raw
    // page object has none, which produced `refresh_undefined` alarms.
    return storeIdentity(msg.identity).then((stored) => {
      scheduleRefreshFor(stored);
      updateBadge();
      return { ok: true };
    });
  },

  // Popup asks: what's my identity?
  GET_ACTIVE_IDENTITY: () =>
    getActiveIdentity().then((id) => ({ identity: id })).catch(() => ({ identity: null })),

  // Popup asks: all identities (for the role-switch UI)
  GET_ALL_IDENTITIES: () =>
    getAllIdentities().then((arr) => ({ identities: arr })).catch(() => ({ identities: [] })),

  // Popup: switch active identity
  SET_ACTIVE_IDENTITY: (msg) => {
    if (!msg.id) return { ok: false, error: 'no id' };
    return setActiveIdentity(msg.id).then(() => { updateBadge(); return { ok: true }; });
  },

  // Popup: refresh now (manual)
  REFRESH_NOW: (msg) => {
    if (!msg.id) return { ok: false, error: 'no id' };
    return refreshIdentity(msg.id).then((id) => ({ ok: true, identity: id }));
  },

  // Popup: revoke the current token at the server, then forget it
  REVOKE_IDENTITY: (msg) => {
    if (!msg.id) return { ok: false, error: 'no id' };
    return revokeAndRemove(msg.id).then(() => { updateBadge(); return { ok: true }; });
  },

  // Popup: signature mode preference. AP8-44 (#237): the context menu really
  // reads this now — there is one menu entry, and it signs in the stored mode.
  GET_SIGN_MODE: () => getSignMode().then((mode) => ({ mode })),
  SET_SIGN_MODE: (msg) => {
    if (!msg.mode) return { ok: false, error: 'no mode' };
    return chrome.storage.local.set({ [STORAGE_SIGN_MODE]: normaliseSignMode(msg.mode) })
      .then(() => ({ ok: true }));
  },

  // Content script: text to sign, coming back from REQUEST_TEXT_FOR_SIGN.
  SIGN_REQUEST: (msg, sender) => {
    if (msg.text == null || !msg.domain) return { ok: false, error: 'no text or domain' };
    const tabId = sender.tab?.id;
    return createSignatureSlug(msg.text, msg.domain, msg.mode)
      .then((marker) => {
        if (tabId) chrome.tabs.sendMessage(tabId, { type: 'INSERT_SIGNATURE', mode: msg.mode, marker });
        return { ok: true };
      })
      .catch((e) => {
        if (tabId) chrome.tabs.sendMessage(tabId, { type: 'SIGN_ERROR', error: e.message });
        return { ok: false, error: e.message };
      });
  }
};

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const handler = msg && HANDLERS[msg.type];
  if (!handler) return;
  let result;
  try { result = handler(msg, sender); } catch (e) { sendResponse({ ok: false, error: e.message }); return; }
  if (result && typeof result.then === 'function') {
    result.then(sendResponse, (e) => sendResponse({ ok: false, error: e.message }));
    return true;   // keep the channel open
  }
  sendResponse(result);
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
  return enriched;
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

// ─── Auto-refresh ────────────────────────────────────────────────────────────
function scheduleRefreshFor(identity) {
  const fireAt = refreshFireAt(identity);
  if (fireAt === null) return;
  if (fireAt <= Date.now()) { refreshIdentity(identity.id).catch(() => {}); return; }
  try { chrome.alarms.create(alarmNameFor(identity.id), { when: fireAt }); } catch (e) { /* no alarms API */ }
}

chrome.alarms?.onAlarm.addListener((alarm) => {
  const id = idFromAlarmName(alarm.name);
  if (id) refreshIdentity(id).catch(() => {});
});

async function refreshIdentity(id) {
  const list = await getAllIdentities();
  const idx  = list.findIndex(i => i.id === id);
  if (idx < 0) throw new Error('identity not found');
  const ident = list[idx];
  if (!ident.refreshToken) throw new Error('no refresh token');

  const res = await fetch(`${issuerBase(ident)}/hhttps/token/refresh`, {
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

  // AP3-18 (#116): the refresh token ROTATES — keep the new one.
  list[idx] = applyRefresh(ident, data);
  await chrome.storage.local.set({ [STORAGE_IDENTITIES]: list });
  scheduleRefreshFor(list[idx]);
  return list[idx];
}

async function revokeAndRemove(id) {
  const list = await getAllIdentities();
  const ident = list.find(i => i.id === id);
  if (!ident) return;

  try {
    await fetch(`${issuerBase(ident)}/hhttps/revoke`, {
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
// AP8-30 (#249): the badge shows the ACTIVE IDENTITY, which is the same on
// every tab. It used to be set per tab, which meant one chrome.storage.local
// read per open tab on every identity change. One read, one global badge.
async function updateBadge() {
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
    title = chrome.i18n.getMessage('badgeTitleLoggedOut');
  }

  try {
    chrome.action.setBadgeText({ text });
    chrome.action.setBadgeBackgroundColor({ color });
    chrome.action.setTitle({ title });
  } catch (e) { /* action API unavailable (tests, teardown) */ }
}

// ─── Lifecycle ───────────────────────────────────────────────────────────────
async function onWake() {
  setupContextMenu();
  const list = await getAllIdentities();
  for (const ident of list) scheduleRefreshFor(ident);
  updateBadge();
}
chrome.runtime.onStartup?.addListener(onWake);
chrome.runtime.onInstalled?.addListener(onWake);
onWake();

// ─── Context menu ────────────────────────────────────────────────────────────
// AP8-44 (#237): ONE entry. Which flavour it signs in comes from the popup's
// signature-mode switch, which is what the popup has always claimed to do —
// two hard-wired menu entries meant the switch was written but never read.
function setupContextMenu() {
  try {
    chrome.contextMenus.removeAll(() => {
      chrome.contextMenus.create({
        id: 'hhttps-sign',
        title: chrome.i18n.getMessage('ctxSign'),
        contexts: ['editable']
      });
    });
  } catch (e) { /* contextMenus API unavailable */ }
}

async function getSignMode() {
  const r = await chrome.storage.local.get([STORAGE_SIGN_MODE]);
  return normaliseSignMode(r[STORAGE_SIGN_MODE]);
}

chrome.contextMenus?.onClicked.addListener(async (info, tab) => {
  if (!tab?.id || info.menuItemId !== 'hhttps-sign') return;
  const ident = await getActiveIdentity();
  if (!ident) {
    chrome.tabs.create({ url: ISSUER_BASE });
    return;
  }
  const mode = await getSignMode();
  // Always need the current text + the page domain. Ask the content script.
  try { chrome.tabs.sendMessage(tab.id, { type: 'REQUEST_TEXT_FOR_SIGN', mode }); } catch (e) { /* no receiver */ }
});

// Create a signature slug via the server. Both modes use the same endpoint —
// 'beta' sets bindingType "document" (strict text hash check) while 'alpha'
// uses "web" (domain only, loose text hash for a tamper warning).
async function createSignatureSlug(text, domain, mode) {
  const ident = await getActiveIdentity();
  if (!ident) throw new Error(chrome.i18n.getMessage('errNoIdentityStored'));
  if (!text || !text.trim()) throw new Error(chrome.i18n.getMessage('errNoTextToSign'));
  if (!domain) throw new Error(chrome.i18n.getMessage('errNoDomain'));

  const signMode = normaliseSignMode(mode);
  const r = await fetch(`${issuerBase(ident)}/hhttps/signatures`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'HHTTPS-Token':  ident.token
    },
    body: JSON.stringify({
      text,
      mode: signMode,
      bindingType: bindingTypeFor(signMode),
      domain
    })
  });
  if (!r.ok) {
    const j = await r.json().catch(() => ({}));
    throw new Error(j.error || `Server ${r.status}`);
  }
  const data = await r.json();
  if (!data.marker) throw new Error(chrome.i18n.getMessage('errNoMarker'));
  return data.marker;
}

