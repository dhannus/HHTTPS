/**
 * HHTTPS Content Script (v1.1.0)
 *
 * - Reads HHTTPS headers from fetch() and XHR responses
 * - Reads <meta name="hhttps-*"> tags as alternative
 * - Reports state to background worker
 * - On page load, attempts to validate stored token for known HHTTPS issuers
 *
 * Compatible with HHTTPS protocol v0.4.1.
 */

(function () {
  'use strict';

  // ─── Read meta tags (server-injected fallback) ─────────────────────────
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
      token:      m('token'),
      method:     m('method'),
      issuer:     m('issuer'),
      version:    m('version')
    };
  }

  let lastReported = null;

  function extractHeaders(getter) {
    return {
      status:     getter('HHTTPS-Status'),
      human:      getter('HHTTPS-Human'),
      role:       getter('HHTTPS-Role'),
      roleLabel:  getter('HHTTPS-Role-Label'),
      roleIcon:   getter('HHTTPS-Role-Icon'),
      trustScore: getter('HHTTPS-Trust-Score'),
      token:      getter('HHTTPS-Token'),
      method:     getter('HHTTPS-Method'),
      issuer:     getter('HHTTPS-Issuer'),
      version:    getter('HHTTPS-Protocol-Version')
    };
  }

  function reportToBackground(state) {
    if (!state.status) return;
    const sig = JSON.stringify(state);
    if (sig === lastReported) return;
    lastReported = sig;
    try { chrome.runtime.sendMessage({ type: 'HHTTPS_HEADERS', ...state }); } catch {}
  }

  // ─── Patch fetch ────────────────────────────────────────────────────────
  const origFetch = window.fetch;
  window.fetch = async function (...args) {
    const response = await origFetch.apply(this, args);
    try {
      const c = response.clone();
      const state = extractHeaders((h) => c.headers.get(h));
      if (state.status) reportToBackground(state);
    } catch {}
    return response;
  };

  // ─── Patch XHR ───────────────────────────────────────────────────────────
  const X = XMLHttpRequest.prototype;
  const origOpen = X.open;
  const origSend = X.send;

  X.open = function (...args) { this._hhttpsUrl = args[1]; return origOpen.apply(this, args); };
  X.send = function (...args) {
    this.addEventListener('load', () => {
      try {
        const state = extractHeaders((h) => this.getResponseHeader(h));
        if (state.status) reportToBackground(state);
      } catch {}
    });
    return origSend.apply(this, args);
  };

  // ─── Listen for popup state queries ──────────────────────────────────────
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.type === 'GET_STATE') {
      // Return current page's HHTTPS state
      const meta = readMetaTags();
      if (meta.status) {
        sendResponse({
          status:     meta.status,
          human:      meta.human === 'true' || meta.human === true,
          role:       meta.role,
          roleLabel:  meta.roleLabel,
          roleIcon:   meta.roleIcon,
          trustScore: parseInt(meta.trustScore || '0'),
          token:      meta.token,
          method:     meta.method,
          issuer:     meta.issuer,
          version:    meta.version
        });
        return;
      }
      // Otherwise return last seen header state (might be null)
      try {
        const last = lastReported ? JSON.parse(lastReported) : { status: 'none' };
        sendResponse({
          ...last,
          human:      last.human === 'true' || last.human === true,
          trustScore: parseInt(last.trustScore || '0')
        });
      } catch {
        sendResponse({ status: 'none' });
      }
    }
  });

  // ─── On page load: 1) check meta tags 2) check stored token ─────────────
  window.addEventListener('DOMContentLoaded', () => {
    const meta = readMetaTags();
    if (meta.status) {
      reportToBackground(meta);
      return;
    }

    // Try detecting if this site IS an HHTTPS issuer (e.g. hhttps.org itself)
    // by checking for /.well-known/hhttps-configuration
    const base = `${window.location.protocol}//${window.location.host}`;
    fetch(`${base}/.well-known/hhttps-configuration`, {
      method: 'GET',
      mode:   'cors',
      cache:  'no-store'
    })
      .then((r) => (r.ok ? r.json() : null))
      .then((cfg) => {
        if (cfg?.issuer) {
          // This is an HHTTPS issuer — fetch stored token, validate
          chrome.runtime.sendMessage({ type: 'GET_TOKEN', issuer: cfg.issuer }, (resp) => {
            if (!resp?.token) {
              reportToBackground({
                status:  'unverified',
                human:   'false',
                issuer:  cfg.issuer,
                version: cfg.protocol_version
              });
              return;
            }
            // Validate via /hhttps/validate
            fetch(cfg.check_endpoint || `${base}/hhttps/check`, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'HHTTPS-Token': resp.token
              },
              body: '{}'
            })
              .then((r) => r.json())
              .then((d) => {
                if (d?.hhttps?.status === 'verified') {
                  reportToBackground({
                    status:     'verified',
                    human:      String(d.hhttps.human),
                    role:       d.role?.id,
                    roleLabel:  d.role?.label,
                    roleIcon:   d.role?.icon,
                    trustScore: String(d.role?.trustScore || d.hhttps?.trustScore || 0),
                    token:      resp.token,
                    method:     d.hhttps.method,
                    issuer:     d.hhttps.issuer || cfg.issuer,
                    version:    d.hhttps.version || cfg.protocol_version
                  });
                }
              })
              .catch(() => {});
          });
        }
      })
      .catch(() => {});
  });

  // ─── Inject visual indicator (small floating badge in bottom-right) ──────
  let indicatorEl = null;

  function injectPageIndicator(state) {
    if (indicatorEl) indicatorEl.remove();
    if (!state.status || state.status === 'none' || state.status === 'unknown') return;

    indicatorEl = document.createElement('div');
    indicatorEl.id = '__hhttps_indicator__';

    const isVerified = state.status === 'verified' && (state.human === 'true' || state.human === true);
    const palette = isVerified
      ? { bg: '#A8B89E', fg: '#FCFAF5', border: '#889982' }   // sage
      : state.status === 'unverified'
        ? { bg: '#F2B894', fg: '#2D2823', border: '#C97D5B' } // apricot/terra
        : { bg: '#EDE0C8', fg: '#2D2823', border: '#7A6F62' };

    const icon  = isVerified ? '👤' : '🔓';
    const label = isVerified
      ? `HHTTPS ✓ ${state.roleLabel || state.role || 'Verifiziert'}`
      : 'HHTTPS — Unverified';

    indicatorEl.style.cssText = `
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: ${palette.bg};
      border: 1px solid ${palette.border};
      border-radius: 100px;
      padding: 8px 16px 8px 14px;
      display: flex;
      align-items: center;
      gap: 8px;
      font-family: -apple-system, BlinkMacSystemFont, system-ui, sans-serif;
      font-size: 13px;
      font-weight: 500;
      color: ${palette.fg};
      z-index: 2147483647;
      box-shadow: 0 4px 12px rgba(45, 40, 35, 0.15);
      cursor: pointer;
      animation: __hhttps_slide_in 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
    `;

    if (!document.getElementById('__hhttps_style__')) {
      const style = document.createElement('style');
      style.id = '__hhttps_style__';
      style.textContent = `
        @keyframes __hhttps_slide_in {
          from { opacity: 0; transform: translateY(20px); }
          to   { opacity: 1; transform: translateY(0); }
        }
      `;
      document.head.appendChild(style);
    }

    indicatorEl.innerHTML = `
      <span style="font-size:16px">${icon}</span>
      <span>${label}</span>
      ${state.trustScore ? `<span style="opacity:0.7;font-size:11px;margin-left:4px">${state.trustScore}/100</span>` : ''}
      <span style="opacity:0.5;font-size:11px;cursor:pointer;margin-left:4px" data-close="1">✕</span>
    `;

    indicatorEl.addEventListener('click', (e) => {
      if (e.target?.dataset?.close) {
        indicatorEl.remove();
        indicatorEl = null;
        return;
      }
      // Open hhttps.org for more info
      window.open(state.issuer ? state.issuer.replace(/^hhttps:\/\//, 'https://') : 'https://hhttps.org', '_blank');
    });

    document.body.appendChild(indicatorEl);

    // Auto-hide after 8 seconds
    setTimeout(() => {
      if (!indicatorEl) return;
      indicatorEl.style.transition = 'opacity 0.5s, transform 0.5s';
      indicatorEl.style.opacity   = '0';
      indicatorEl.style.transform = 'translateY(10px)';
      setTimeout(() => { indicatorEl?.remove(); indicatorEl = null; }, 500);
    }, 8000);
  }

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === 'INJECT_INDICATOR' && msg.state) injectPageIndicator(msg.state);
  });
})();
