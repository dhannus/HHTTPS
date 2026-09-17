/**
 * HHTTPS Extension — Identity Issuer Content Script
 *
 * Runs ONLY on hhttps.org. Job: capture the user's identity (token + refresh
 * token + role) when it's issued by the hhttps.org page, and forward it to
 * the extension's background worker for storage.
 *
 * Two pickup paths:
 *   1. Live: window.postMessage from hhttps.org's publishIdentity()
 *   2. Existing session: read localStorage on script load
 *
 * The user has already authenticated with their passkey on hhttps.org —
 * we are simply observing the result, not authenticating ourselves.
 */

(function () {
  'use strict';

  // AP8-22 (#249): debug logging is opt-in per page
  // (`localStorage.hhttpsDebug = '1'`), like in content-universal.js.
  const DEBUG = (() => {
    try { return localStorage.getItem('hhttpsDebug') === '1'; } catch { return false; }
  })();
  const debug = (...a) => { if (DEBUG) console.log('[HHTTPS Extension]', ...a); };
  debug('issuer content script active on', location.host);

  // ─── 1) Live capture via postMessage ─────────────────────────────────────
  window.addEventListener('message', (event) => {
    // Security: only accept messages from this same origin
    if (event.origin !== window.location.origin) return;
    if (!event.data || event.data.source !== 'hhttps-org') return;

    if (event.data.type === 'identity-issued' && event.data.payload?.token) {
      debug('identity captured via postMessage');
      forwardToBackground(event.data.payload, 'postMessage');
    }
  });

  // ─── 2) Existing-session capture from localStorage ───────────────────────
  // If the user already had an identity from a previous visit, pick it up now.
  try {
    const raw = localStorage.getItem('hhttps_identity');
    if (raw) {
      const identity = JSON.parse(raw);
      if (identity?.token) {
        debug('identity found in localStorage');
        forwardToBackground(identity, 'storage');
      }
    }
  } catch (e) {
    // localStorage might be unavailable in some contexts — fail silently
  }

  // ─── Forward to background service worker ────────────────────────────────
  // `source` is 'postMessage' (a token was JUST issued on this page) or
  // 'storage' (an identity from an earlier visit, picked up on load).
  function forwardToBackground(identity, source) {
    try {
      chrome.runtime.sendMessage(
        { type: 'IDENTITY_CAPTURED', identity },
        (response) => {
          if (chrome.runtime.lastError) {
            // background worker might be inactive — that's fine, message
            // will be re-attempted on next page load
            return;
          }
          if (response?.ok && source === 'postMessage') {
            // Small subtle indicator that the extension picked up the identity
            // (only shown on hhttps.org so it doesn't clutter other pages).
            showCapturedToast(identity);
          }
        }
      );
    } catch (e) {
      // Extension context invalidated (during dev reload) — ignore
    }
  }

  function showCapturedToast(identity) {
    // Once per page, no matter how many identity-issued events arrive.
    // AP8-52 (#249): whether this is a FRESH issuance is decided by the caller
    // now (source === 'postMessage'). It used to be guessed from the document's
    // load state, so the toast fired on a slow load and stayed silent on a fast
    // one — the opposite of what the comment next to it claimed.
    if (window.__hhttpsToastShown) return;
    window.__hhttpsToastShown = true;

    const t = document.createElement('div');
    t.style.cssText = `
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: linear-gradient(135deg, #5BAF6B, #889982);
      color: #FCFAF5;
      padding: 14px 20px 14px 16px;
      border-radius: 100px;
      font-family: 'Inter', -apple-system, system-ui, sans-serif;
      font-size: 13px;
      font-weight: 500;
      box-shadow: 0 8px 24px rgba(45, 40, 35, 0.2);
      z-index: 2147483647;
      display: flex;
      align-items: center;
      gap: 10px;
      animation: hh-slide-in 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
    `;
    const icon = identity.roleIcon || '👤';
    const label = identity.roleLabel || identity.role || 'Verified';
    t.innerHTML = `<span style="font-size:18px">${icon}</span>
      <span>${chrome.i18n.getMessage('identitySaved', [label])}</span>`;

    if (!document.getElementById('__hhttps_toast_style')) {
      const s = document.createElement('style');
      s.id = '__hhttps_toast_style';
      s.textContent = `@keyframes hh-slide-in {
        from { opacity: 0; transform: translateY(20px); }
        to   { opacity: 1; transform: translateY(0); }
      }`;
      document.head.appendChild(s);
    }

    document.body.appendChild(t);
    setTimeout(() => {
      t.style.transition = 'opacity 0.4s, transform 0.4s';
      t.style.opacity = '0';
      t.style.transform = 'translateY(10px)';
      setTimeout(() => t.remove(), 400);
    }, 3500);
  }
})();
