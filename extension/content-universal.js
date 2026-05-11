/**
 * HHTTPS Extension — Universal Content Script
 *
 * Runs on every page. Currently focused on:
 *   - Reading HHTTPS-* response headers (legacy compatibility)
 *   - Detecting <meta name="hhttps-*"> tags
 *   - Reporting page state to background worker
 *
 * In Phase 2 this will gain:
 *   - HHTTPS signature detection in page text
 *   - Inline seal rendering next to verified content
 *   - Right-click "sign with HHTTPS identity" on input fields
 */

(function () {
  'use strict';

  // ─── 1) Read meta tags (server-injected fallback) ────────────────────────
  function readMetaTags() {
    const m = (name) => {
      const el = document.querySelector(`meta[name="hhttps-${name}"]`);
      return el ? el.getAttribute('content') : null;
    };
    return {
      status:     m('status'),
      human:      m('human'),
      role:       m('role'),
      roleLabel:  m('role-label'),
      roleIcon:   m('role-icon'),
      trustScore: m('trust-score'),
      method:     m('method'),
      issuer:     m('issuer'),
      version:    m('version')
    };
  }

  let lastReportedSig = null;

  function reportPageState(state) {
    if (!state || !state.status) return;
    const sig = JSON.stringify(state);
    if (sig === lastReportedSig) return;
    lastReportedSig = sig;
    try {
      chrome.runtime.sendMessage({ type: 'PAGE_STATE', state });
    } catch (e) {}
  }

  // ─── 2) Patch fetch() and XHR to read HHTTPS-* headers ───────────────────
  function extractHeaders(getter) {
    return {
      status:     getter('HHTTPS-Status'),
      human:      getter('HHTTPS-Human'),
      role:       getter('HHTTPS-Role'),
      roleLabel:  getter('HHTTPS-Role-Label'),
      roleIcon:   getter('HHTTPS-Role-Icon'),
      trustScore: getter('HHTTPS-Trust-Score'),
      method:     getter('HHTTPS-Method'),
      issuer:     getter('HHTTPS-Issuer'),
      version:    getter('HHTTPS-Protocol-Version')
    };
  }

  const origFetch = window.fetch;
  if (origFetch) {
    window.fetch = async function (...args) {
      const r = await origFetch.apply(this, args);
      try {
        const c = r.clone();
        const state = extractHeaders((h) => c.headers.get(h));
        if (state.status) reportPageState(state);
      } catch (e) {}
      return r;
    };
  }

  const X = XMLHttpRequest.prototype;
  const origSend = X.send;
  X.send = function (...args) {
    this.addEventListener('load', () => {
      try {
        const state = extractHeaders((h) => this.getResponseHeader(h));
        if (state.status) reportPageState(state);
      } catch (e) {}
    });
    return origSend.apply(this, args);
  };

  // ─── 3) On DOM ready, check meta tags ─────────────────────────────────────
  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    initMetaCheck();
  } else {
    document.addEventListener('DOMContentLoaded', initMetaCheck);
  }

  function initMetaCheck() {
    const meta = readMetaTags();
    if (meta.status) reportPageState(meta);
  }

  // ─── 4) Respond to popup queries about this page ─────────────────────────
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg?.type === 'GET_PAGE_STATE') {
      const meta = readMetaTags();
      if (meta.status) {
        sendResponse({
          ...meta,
          human:      meta.human === 'true' || meta.human === true,
          trustScore: parseInt(meta.trustScore || '0')
        });
        return;
      }
      try {
        const last = lastReportedSig ? JSON.parse(lastReportedSig) : { status: 'none' };
        sendResponse({
          ...last,
          human:      last.human === 'true' || last.human === true,
          trustScore: parseInt(last.trustScore || '0')
        });
      } catch (e) {
        sendResponse({ status: 'none' });
      }
    }
  });

  // Phase 2 hooks (not active yet, just placeholders):
  //   - scanForSignatures(): walk text nodes, find [HHTTPS:role:trust:jwt] patterns
  //   - renderInlineSeals(): replace patterns with floating seal UI elements
  //   - handleSignAction(): respond to "sign this text" from popup
})();
