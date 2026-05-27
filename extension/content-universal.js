/**
 * HHTTPS Extension — Universal Content Script v1.4.0
 *
 * Phase 2.5: Slug-based signatures with domain binding.
 *
 *   - Primary marker:  #hhttps:s:<slug>   (12-char short, anti-theft)
 *   - Legacy markers:  #hhttps:a:<token>  /  #hhttps:b:<sig>   (still rendered
 *                      but flagged as legacy with a different visual)
 *
 *   - Signing flow:    user clicks right-click → content script collects
 *                      current text + page domain → background creates slug
 *                      via server → marker is inserted
 *
 *   - Verify flow:     all slugs on a page are gathered, then batched in
 *                      one POST /hhttps/signatures/batch with the current
 *                      domain. Server checks domain binding + text hash.
 *
 *   - Seals reflect:   valid (sage/green) · wrong-domain (amber warning) ·
 *                      text-modified (apricot) · revoked (red) · legacy (gray)
 */

(function () {
  'use strict';

  // ─── Marker patterns ─────────────────────────────────────────────────────
  // New format (Phase 2.5+): short slug
  const MARKER_SLUG_RE  = /#hhttps:s:(hp-[A-Z0-9\-]{8,16})/gi;
  // Legacy format (v1.3): full JWT in the marker
  const MARKER_LEGACY_ALPHA_RE = /#hhttps:a:([A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)/g;
  const MARKER_LEGACY_BETA_RE  = /#hhttps:b:([A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)/g;

  const SEAL_CLASS   = '__hhttps-seal__';
  const SEAL_WRAPPER = '__hhttps-wrapped__';
  const SKIP_TAGS = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEXTAREA',
                             'INPUT', 'CODE', 'PRE', 'KBD', 'SAMP']);

  // ISSUER override (default hhttps.org; can be configured later for multi-issuer)
  const DEFAULT_ISSUER_BASE = 'https://hhttps.org';

  // Local cache: slug → result + timestamp (5 min)
  const slugCache = new Map();
  const CACHE_TTL = 5 * 60_000;

  // Track scans for popup stats
  let scanCount = { slug: 0, legacy: 0 };
  let lastFocusedEditable = null;

  // ─── Page state reading (carried over) ───────────────────────────────────
  let lastReportedSig = null;
  function reportPageState(state) {
    if (!state || !state.status) return;
    const sig = JSON.stringify(state);
    if (sig === lastReportedSig) return;
    lastReportedSig = sig;
    try { chrome.runtime.sendMessage({ type: 'PAGE_STATE', state }); } catch (e) {}
  }
  function readMetaTags() {
    const m = (n) => {
      const el = document.querySelector(`meta[name="hhttps-${n}"]`);
      return el ? el.getAttribute('content') : null;
    };
    return {
      status: m('status'), human: m('human'), role: m('role'),
      roleLabel: m('role-label'), roleIcon: m('role-icon'),
      trustScore: m('trust-score'), method: m('method'),
      issuer: m('issuer'), version: m('version')
    };
  }

  // ─── Domain utility (for sending current page's domain to verify) ────────
  function getCurrentDomain() {
    try {
      return new URL(window.location.href).hostname;
    } catch (e) {
      return null;
    }
  }

  // ─── Scanner: walk DOM, find markers, queue verification ─────────────────
  function scanForSignatures(root) {
    if (!root) root = document.body;
    if (!root || !root.nodeType) return;

    // Recursively scan accessible iframes (same-origin or about:blank).
    // Email clients, Reddit/Disqus embeds, and many forums render content in
    // sandboxed iframes — without this, markers inside them never get sealed.
    scanIframesIn(root);

    const walker = createMarkerWalker(root, root.ownerDocument || document);

    const toProcess = [];
    let n;
    while ((n = walker.nextNode())) toProcess.push(n);

    // First pass: collect all unique slugs on the page (for batch verify)
    const slugs = new Set();
    for (const node of toProcess) {
      const t = node.textContent;
      let m;
      MARKER_SLUG_RE.lastIndex = 0;
      while ((m = MARKER_SLUG_RE.exec(t)) !== null) slugs.add(m[1]);
    }

    // Issue batch verify for new slugs (not in cache or expired)
    const slugsToFetch = [];
    for (const slug of slugs) {
      const cached = slugCache.get(slug);
      if (!cached || (Date.now() - cached.fetchedAt) > CACHE_TTL) {
        slugsToFetch.push(slug);
      }
    }
    if (slugs.size > 0) {
      console.log('[HHTTPS] found slugs to verify:', Array.from(slugs), 'to fetch:', slugsToFetch.length);
    }
    if (slugsToFetch.length > 0) {
      batchVerifySlugs(slugsToFetch).catch((e) => console.warn('[HHTTPS] batch failed:', e));
    }

    // Second pass: process each text node, replace markers with placeholders
    for (const node of toProcess) {
      processTextNode(node);
    }
  }

  // Build a TreeWalker that filters text nodes for markers. Pulled out as a
  // helper so iframe scanning can reuse the same logic with a different doc.
  function createMarkerWalker(root, doc) {
    return (doc || document).createTreeWalker(root, NodeFilter.SHOW_TEXT, {
      acceptNode: (node) => {
        if (!node.parentElement) return NodeFilter.FILTER_REJECT;
        if (SKIP_TAGS.has(node.parentElement.tagName)) return NodeFilter.FILTER_REJECT;
        if (node.parentElement.closest(`.${SEAL_WRAPPER}`)) return NodeFilter.FILTER_REJECT;
        if (node.parentElement.closest('[contenteditable="true"]')) return NodeFilter.FILTER_REJECT;
        const t = node.textContent;
        if (!t || (!t.includes('#hhttps:s:') &&
                   !t.includes('#hhttps:a:') &&
                   !t.includes('#hhttps:b:'))) return NodeFilter.FILTER_REJECT;
        return NodeFilter.FILTER_ACCEPT;
      }
    });
  }

  // Walk every iframe under `root` and recurse if we can reach its document.
  // Cross-origin iframes throw on `contentDocument` access — we catch and skip.
  //
  // Webmail clients (Strato, Gmail, Outlook Web) and many forum embeds write
  // their iframe content asynchronously. We can't rely on the `load` event
  // because some use `srcdoc=` or `document.write()` which don't fire `load`
  // reliably. Belt-and-braces: hook `load`, watch the iframe's body via
  // MutationObserver, AND poll for late content as a fallback.
  const iframesHooked = new WeakSet();
  const IFRAME_POLL_INTERVAL_MS = 1500;
  const IFRAME_POLL_MAX_ATTEMPTS = 20;   // 30 seconds total

  function scanIframesIn(root) {
    const iframes = root.nodeType === 1 && root.tagName === 'IFRAME'
      ? [root]
      : Array.from(root.querySelectorAll ? root.querySelectorAll('iframe') : []);

    for (const iframe of iframes) {
      tryHookIframe(iframe);
    }
  }

  function tryHookIframe(iframe) {
    let doc;
    try {
      doc = iframe.contentDocument;
    } catch (e) {
      return;  // Cross-origin — silently skip
    }
    if (!doc) return;

    const isAlreadyHooked = iframesHooked.has(iframe);
    const bodyLen = doc.body ? (doc.body.innerHTML || '').length : -1;
    const markerInBody = doc.body && (doc.body.innerHTML || '').includes('#hhttps:s:');
    console.log('[HHTTPS] iframe hook', {
      hookedBefore: isAlreadyHooked,
      bodyLen,
      markerInBody,
      iframeClass: iframe.className,
      iframeSrc: iframe.src || '(srcdoc/about:blank)'
    });

    // Always (re)inject styles + scan, even if we've hooked it before — the
    // iframe content may have changed since.
    try {
      injectStylesInto(doc);
      if (doc.body) scanForSignatures(doc.body);
    } catch (e) {}

    // First time we see this iframe? Set up persistent watchers.
    if (iframesHooked.has(iframe)) return;
    iframesHooked.add(iframe);

    // Hook 1: load event (works for src= iframes)
    iframe.addEventListener('load', () => {
      try {
        const d = iframe.contentDocument;
        if (d) {
          injectStylesInto(d);
          if (d.body) scanForSignatures(d.body);
          watchDocument(d);
        }
      } catch (e) {}
    });

    // Hook 2: MutationObserver on iframe element (catches srcdoc changes)
    try {
      const attrObserver = new MutationObserver(() => {
        try {
          const d = iframe.contentDocument;
          if (d) {
            injectStylesInto(d);
            if (d.body) scanForSignatures(d.body);
            watchDocument(d);
          }
        } catch (e) {}
      });
      attrObserver.observe(iframe, {
        attributes: true,
        attributeFilter: ['src', 'srcdoc']
      });
    } catch (e) {}

    // Hook 3: MutationObserver on the iframe's body (catches dynamic content
    // written into the iframe after its document is ready)
    if (doc.body) {
      watchDocument(doc);
    } else {
      // Body not yet there — defer to readystate
      doc.addEventListener?.('DOMContentLoaded', () => {
        try { if (doc.body) { injectStylesInto(doc); scanForSignatures(doc.body); watchDocument(doc); } }
        catch (e) {}
      });
    }

    // Hook 4: Polling fallback for the worst-case async writers
    let attempts = 0;
    const poller = setInterval(() => {
      attempts++;
      let stillThere = false;
      try { stillThere = document.contains(iframe); } catch (e) {}
      if (!stillThere || attempts > IFRAME_POLL_MAX_ATTEMPTS) {
        clearInterval(poller);
        return;
      }
      try {
        const d = iframe.contentDocument;
        if (!d || !d.body) return;
        // Found content — scan + then stop polling once content is processed
        const hasContent = (d.body.innerHTML || '').length > 0;
        if (hasContent) {
          injectStylesInto(d);
          scanForSignatures(d.body);
          watchDocument(d);
          // If markers were found and turned into seals, we can stop.
          const sealsNow = d.querySelectorAll(`.${SEAL_CLASS}`).length;
          if (sealsNow > 0 || attempts >= IFRAME_POLL_MAX_ATTEMPTS) {
            clearInterval(poller);
          }
        }
      } catch (e) {
        clearInterval(poller);
      }
    }, IFRAME_POLL_INTERVAL_MS);
  }

  function processTextNode(textNode) {
    const text = textNode.textContent;
    const matches = [];

    let m;
    MARKER_SLUG_RE.lastIndex = 0;
    while ((m = MARKER_SLUG_RE.exec(text)) !== null) {
      matches.push({ start: m.index, end: m.index + m[0].length,
                     id: m[1], type: 'slug' });
    }
    MARKER_LEGACY_ALPHA_RE.lastIndex = 0;
    while ((m = MARKER_LEGACY_ALPHA_RE.exec(text)) !== null) {
      matches.push({ start: m.index, end: m.index + m[0].length,
                     token: m[1], type: 'legacy-alpha' });
    }
    MARKER_LEGACY_BETA_RE.lastIndex = 0;
    while ((m = MARKER_LEGACY_BETA_RE.exec(text)) !== null) {
      matches.push({ start: m.index, end: m.index + m[0].length,
                     token: m[1], type: 'legacy-beta' });
    }
    if (!matches.length) return;
    matches.sort((a, b) => a.start - b.start);

    // Use the text node's owning document so iframe content stays in iframe
    const doc = textNode.ownerDocument || document;
    const wrapper = doc.createElement('span');
    wrapper.className = SEAL_WRAPPER;

    let cursor = 0;
    for (const match of matches) {
      if (match.start > cursor) {
        wrapper.appendChild(doc.createTextNode(text.slice(cursor, match.start)));
      }

      const seal = createSealPlaceholder(match.type, doc);

      if (match.type === 'slug') {
        scanCount.slug++;
        const cached = slugCache.get(match.id);
        if (cached && cached.data) {
          renderSealFromBatchResult(seal, cached.data);
        } else {
          seal.setAttribute('data-slug', match.id);
        }
      } else {
        scanCount.legacy++;
        renderSealLegacy(seal, match.type);
      }

      wrapper.appendChild(seal);
      cursor = match.end;
    }
    if (cursor < text.length) {
      wrapper.appendChild(doc.createTextNode(text.slice(cursor)));
    }
    textNode.replaceWith(wrapper);
  }

  // ─── Seal placeholder + render ───────────────────────────────────────────
  function createSealPlaceholder(type, doc) {
    const d = doc || document;
    const span = d.createElement('span');
    span.className = SEAL_CLASS;
    span.setAttribute('data-type', type);
    span.setAttribute('data-state', 'pending');
    span.innerHTML = `<span class="hh-seal-icon">⏳</span><span class="hh-seal-label">${chrome.i18n.getMessage('sealChecking')}</span>`;
    return span;
  }

  function renderSealFromBatchResult(sealEl, result) {
    if (!result || result.status === 'unknown') {
      sealEl.setAttribute('data-state', 'invalid');
      sealEl.innerHTML = `<span class="hh-seal-icon">?</span><span class="hh-seal-label">Unbekannte Signatur</span>`;
      return;
    }
    if (result.status === 'revoked') {
      sealEl.setAttribute('data-state', 'revoked');
      sealEl.innerHTML = `<span class="hh-seal-icon">🚫</span><span class="hh-seal-label">Widerrufen</span>`;
      attachClickHandler(sealEl, result);
      return;
    }
    if (result.status === 'wrong-domain') {
      sealEl.setAttribute('data-state', 'wrong-domain');
      sealEl.innerHTML = `<span class="hh-seal-icon">⚠</span><span class="hh-seal-label">Falsche Domain</span>`;
      attachClickHandler(sealEl, result);
      return;
    }
    if (result.status === 'text-modified') {
      sealEl.setAttribute('data-state', 'mismatch');
      const icon = (result.role && result.role.icon) || '👤';
      sealEl.innerHTML = `<span class="hh-seal-icon">${icon}</span><span class="hh-seal-label">${chrome.i18n.getMessage('sealTextChanged')}</span>`;
      attachClickHandler(sealEl, result);
      return;
    }
    // Valid
    const role = result.role || {};
    const icon = role.icon || '👤';
    const label = role.label || role.id || chrome.i18n.getMessage('roleFallback');
    const trust = role.trustScore != null ? role.trustScore : '?';
    sealEl.setAttribute('data-state', 'valid');
    sealEl.setAttribute('data-trust', trust);
    sealEl.innerHTML = `
      <span class="hh-seal-icon">${icon}</span>
      <span class="hh-seal-label">${escapeHtml(label)}</span>
      <span class="hh-seal-trust">${trust}</span>
    `;
    attachClickHandler(sealEl, result);
  }

  function renderSealLegacy(sealEl, type) {
    sealEl.setAttribute('data-state', 'legacy');
    const subtype = type === 'legacy-beta' ? 'beta' : 'alpha';
    sealEl.innerHTML = `
      <span class="hh-seal-icon">⚠</span>
      <span class="hh-seal-label">Legacy ${subtype}</span>
    `;
    sealEl.setAttribute('title',
      chrome.i18n.getMessage('oldFormatWarning'));
  }

  function attachClickHandler(sealEl, data) {
    sealEl.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      showDetailCard(sealEl, data);
    });
  }

  function showDetailCard(sealEl, data) {
    document.querySelectorAll('.__hhttps-detail__').forEach(n => n.remove());

    const role = data.role || {};
    const binding = data.binding || {};
    const card = document.createElement('div');
    card.className = '__hhttps-detail__';

    let statusBanner = '';
    if (data.status === 'verified') {
      statusBanner = `<div class="hh-d-status hh-d-status-ok">${chrome.i18n.getMessage('detailVerified')}</div>`;
    } else if (data.status === 'wrong-domain') {
      statusBanner = `<div class="hh-d-status hh-d-status-warn">${chrome.i18n.getMessage('detailWrongDomainTitle')}
        ${chrome.i18n.getMessage('detailIssuedFor')} <b>${escapeHtml(data.expected || binding.domain || '?')}</b><br>
        ${chrome.i18n.getMessage('detailUsedOn')} <b>${escapeHtml(data.observed || getCurrentDomain() || '?')}</b></div>`;
    } else if (data.status === 'text-modified') {
      statusBanner = `<div class="hh-d-status hh-d-status-warn">${chrome.i18n.getMessage('detailTextModified')}</div>`;
    } else if (data.status === 'revoked') {
      statusBanner = `<div class="hh-d-status hh-d-status-bad">${chrome.i18n.getMessage('detailRevokedOn', [formatDate(data.revokedAt)])}</div>`;
    }

    const issuerHost = 'hhttps.org';
    const slugUrl = `https://${issuerHost}/s/${data.id || ''}`;

    card.innerHTML = `
      <div class="hh-d-head">
        <span class="hh-d-icon">${role.icon || '👤'}</span>
        <div>
          <div class="hh-d-role">${escapeHtml(role.label || chrome.i18n.getMessage('roleFallback'))}</div>
          <div class="hh-d-sub">Trust ${role.trustScore || '?'}/100${role.levelLabel ? ' · ' + escapeHtml(role.levelLabel) : ''}</div>
        </div>
        <button class="hh-d-close" aria-label="${chrome.i18n.getMessage('detailClose')}">×</button>
      </div>
      ${statusBanner}
      <div class="hh-d-rows">
        <div class="hh-d-row"><span>${chrome.i18n.getMessage('rowSignature')}</span><b>${escapeHtml(data.id || '?')}</b></div>
        ${binding.domain ? `<div class="hh-d-row"><span>${chrome.i18n.getMessage('rowBoundTo')}</span><b>${escapeHtml(binding.domain)}</b></div>` : ''}
        ${binding.type ? `<div class="hh-d-row"><span>${chrome.i18n.getMessage('rowBindingType')}</span><b>${escapeHtml(binding.type)}</b></div>` : ''}
        ${data.createdAt ? `<div class="hh-d-row"><span>${chrome.i18n.getMessage('rowSignedOn')}</span><b>${formatDate(data.createdAt)}</b></div>` : ''}
        ${data.textPreview ? `<div class="hh-d-row hh-d-row-block"><span>${chrome.i18n.getMessage('rowTextExcerpt')}</span><div class="hh-d-preview">${escapeHtml(data.textPreview)}</div></div>` : ''}
      </div>
      <div class="hh-d-foot">
        <a href="${escapeHtml(slugUrl)}" target="_blank">${chrome.i18n.getMessage('viewOnHhttps')}</a>
      </div>
    `;

    const r = sealEl.getBoundingClientRect();
    card.style.position = 'fixed';
    card.style.top  = Math.min(window.innerHeight - 320, r.bottom + 8) + 'px';
    card.style.left = Math.max(8, Math.min(window.innerWidth - 320, r.left)) + 'px';

    document.body.appendChild(card);
    card.querySelector('.hh-d-close').addEventListener('click', () => card.remove());
    setTimeout(() => {
      const closer = (ev) => {
        if (!card.contains(ev.target) && ev.target !== sealEl) {
          card.remove();
          document.removeEventListener('click', closer);
        }
      };
      document.addEventListener('click', closer);
    }, 0);
  }

  // ─── Batch verify via server ─────────────────────────────────────────────
  async function batchVerifySlugs(slugs) {
    const domain = getCurrentDomain();
    if (!domain) return;

    // We don't send text previews anymore — they're only useful for
    // `document` (Beta) bindings, which aren't user-facing yet. For Alpha
    // bindings the server ignores them; sending them caused false positives
    // because HTML rendering mutates whitespace, entities, and quoting.
    // When Beta sign-mode comes back, we'll collect previews selectively for
    // those slugs only.
    try {
      const r = await fetch(`${DEFAULT_ISSUER_BASE}/hhttps/signatures/batch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ slugs, domain })
      });
      if (!r.ok) {
        console.warn('[HHTTPS] batch verify HTTP', r.status);
        return;
      }
      const data = await r.json();
      const results = data.results || {};
      console.log('[HHTTPS] batch verify response:', Object.keys(results).length, 'results');
      for (const [slug, result] of Object.entries(results)) {
        slugCache.set(slug, { data: result, fetchedAt: Date.now() });
        // Update pending seals in main doc AND in accessible iframes
        const docs = [document];
        try {
          for (const iframe of document.querySelectorAll('iframe')) {
            try { if (iframe.contentDocument) docs.push(iframe.contentDocument); }
            catch (e) {}
          }
        } catch (e) {}
        for (const doc of docs) {
          doc.querySelectorAll(`.${SEAL_CLASS}[data-slug="${slug}"]`).forEach(seal => {
            renderSealFromBatchResult(seal, result);
          });
        }
      }
    } catch (e) {
      console.warn('[HHTTPS] batch verify failed:', e);
    }
  }

  // Collect surrounding text for a slug occurrence (for text tampering check).
  // Looks in the main document and all accessible iframes — the marker often
  // lives in an email body iframe etc.
  function collectContextForSlug(slug) {
    const needle = `#hhttps:s:${slug}`;
    const searchTexts = [document.body?.innerText || ''];
    try {
      const iframes = document.querySelectorAll('iframe');
      for (const iframe of iframes) {
        try {
          const body = iframe.contentDocument?.body;
          if (body) searchTexts.push(body.innerText || '');
        } catch (e) { /* cross-origin */ }
      }
    } catch (e) {}

    for (const allText of searchTexts) {
      const idx = allText.indexOf(needle);
      if (idx < 0) continue;
      const start = Math.max(0, idx - 200);
      const end   = Math.min(allText.length, idx + 200);
      const windowText = allText.slice(start, end);
      return windowText.replace(new RegExp(`#hhttps:s:${slug}`, 'g'), '').trim();
    }
    return null;
  }

  // ─── HTML escape + date format ───────────────────────────────────────────
  function escapeHtml(s) {
    if (s == null) return '';
    return String(s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
  function formatDate(iso) {
    if (!iso) return '';
    try {
      const d = new Date(iso);
      return d.toLocaleDateString('de-DE', { day: '2-digit', month: 'short', year: 'numeric' });
    } catch (e) { return iso; }
  }

  // ─── CSS injection ───────────────────────────────────────────────────────
  function injectStyles() {
    injectStylesInto(document);
  }

  function injectStylesInto(doc) {
    if (!doc || doc.getElementById('__hhttps_seal_style__')) return;
    const s = doc.createElement('style');
    s.id = '__hhttps_seal_style__';
    s.textContent = `
      .${SEAL_CLASS} {
        display: inline-flex !important;
        align-items: center;
        gap: 4px;
        padding: 1px 8px 1px 6px !important;
        margin: 0 1px;
        border-radius: 100px;
        background: linear-gradient(135deg, #F8F1E4, #FCFAF5);
        border: 1px solid rgba(45,40,35,0.12);
        color: #2D2823;
        font-family: -apple-system, BlinkMacSystemFont, 'Inter', system-ui, sans-serif;
        font-size: 0.85em;
        line-height: 1.4;
        cursor: pointer;
        vertical-align: baseline;
        white-space: nowrap;
        transition: transform 0.15s, box-shadow 0.15s;
      }
      .${SEAL_CLASS}:hover {
        transform: translateY(-1px);
        box-shadow: 0 2px 8px rgba(45,40,35,0.12);
      }
      .${SEAL_CLASS}[data-state="valid"] {
        background: linear-gradient(135deg, #5BAF6B, #889982);
        color: #FCFAF5;
        border-color: rgba(255,255,255,0.3);
      }
      .${SEAL_CLASS}[data-state="valid"][data-trust^="9"] {
        background: linear-gradient(135deg, #5BAF6B, #4A9A5A);
      }
      .${SEAL_CLASS}[data-state="valid"][data-trust^="3"],
      .${SEAL_CLASS}[data-state="valid"][data-trust^="4"],
      .${SEAL_CLASS}[data-state="valid"][data-trust^="5"] {
        background: linear-gradient(135deg, #F2B894, #E89F73);
        color: #2D2823;
      }
      .${SEAL_CLASS}[data-state="wrong-domain"],
      .${SEAL_CLASS}[data-state="mismatch"] {
        background: linear-gradient(135deg, #F2B894, #C97D5B);
        color: #FCFAF5;
      }
      .${SEAL_CLASS}[data-state="revoked"],
      .${SEAL_CLASS}[data-state="invalid"] {
        background: linear-gradient(135deg, #DDB4B0, #C97D5B);
        color: #FCFAF5;
      }
      .${SEAL_CLASS}[data-state="legacy"] {
        background: linear-gradient(135deg, #C0B8AA, #9A9080);
        color: #FCFAF5;
        cursor: help;
      }
      .${SEAL_CLASS} .hh-seal-icon { font-size: 1.05em; line-height: 1; }
      .${SEAL_CLASS} .hh-seal-label { font-weight: 500; }
      .${SEAL_CLASS} .hh-seal-trust {
        font-size: 0.75em; opacity: 0.9;
        font-family: 'JetBrains Mono', ui-monospace, monospace;
        padding: 0 4px;
        border-left: 1px solid rgba(255,255,255,0.35);
        margin-left: 2px;
      }
      .__hhttps-detail__ {
        position: fixed; z-index: 2147483647;
        width: 320px;
        background: #FCFAF5;
        border-radius: 14px;
        border: 1px solid rgba(45,40,35,0.12);
        box-shadow: 0 12px 32px rgba(45,40,35,0.18);
        color: #2D2823;
        font-family: -apple-system, BlinkMacSystemFont, 'Inter', system-ui, sans-serif;
        font-size: 13px;
        animation: hh-fade-in 0.2s ease;
      }
      @keyframes hh-fade-in {
        from { opacity: 0; transform: translateY(4px); }
        to { opacity: 1; transform: translateY(0); }
      }
      .__hhttps-detail__ .hh-d-head {
        display: flex; align-items: center; gap: 10px;
        padding: 14px 14px 10px;
        border-bottom: 1px solid rgba(45,40,35,0.08);
      }
      .__hhttps-detail__ .hh-d-icon { font-size: 28px; }
      .__hhttps-detail__ .hh-d-role { font-weight: 600; font-size: 14px; }
      .__hhttps-detail__ .hh-d-sub {
        font-size: 11px; color: #7A6F62; margin-top: 2px;
      }
      .__hhttps-detail__ .hh-d-close {
        margin-left: auto;
        background: none; border: none; cursor: pointer;
        color: #7A6F62; font-size: 18px; line-height: 1; padding: 4px 8px;
      }
      .__hhttps-detail__ .hh-d-status {
        padding: 10px 14px;
        font-size: 12px;
        border-bottom: 1px solid rgba(45,40,35,0.08);
      }
      .__hhttps-detail__ .hh-d-status-ok { background: #E8F0E2; color: #2D5A2D; }
      .__hhttps-detail__ .hh-d-status-warn { background: #FDF0DD; color: #8B5523; }
      .__hhttps-detail__ .hh-d-status-bad { background: #F7E1DD; color: #7A2F1F; }
      .__hhttps-detail__ .hh-d-rows {
        padding: 6px 0;
      }
      .__hhttps-detail__ .hh-d-row {
        display: flex; justify-content: space-between; align-items: baseline;
        padding: 6px 14px;
        font-size: 12px;
      }
      .__hhttps-detail__ .hh-d-row span { color: #7A6F62; }
      .__hhttps-detail__ .hh-d-row b { color: #2D2823; font-weight: 600; max-width: 65%; text-align: right; word-break: break-word; }
      .__hhttps-detail__ .hh-d-row-block { flex-direction: column; align-items: stretch; }
      .__hhttps-detail__ .hh-d-row-block span { margin-bottom: 4px; }
      .__hhttps-detail__ .hh-d-preview {
        background: #F8F1E4;
        border-radius: 6px; padding: 8px;
        font-family: 'JetBrains Mono', ui-monospace, monospace;
        font-size: 11px;
        color: #2D2823;
        line-height: 1.5;
      }
      .__hhttps-detail__ .hh-d-foot {
        padding: 10px 14px;
        border-top: 1px solid rgba(45,40,35,0.08);
        background: #F8F1E4;
        border-radius: 0 0 14px 14px;
        text-align: center; font-size: 11px;
      }
      .__hhttps-detail__ .hh-d-foot a {
        color: #A86246; text-decoration: none;
      }
      .__hhttps-detail__ .hh-d-foot a:hover { text-decoration: underline; }
    `;
    (doc.head || doc.documentElement)?.appendChild(s);
  }

  // ─── Mutation observer ───────────────────────────────────────────────────
  function watchMutations() {
    watchDocument(document);
  }

  // Track which documents we already attached observers to (avoids duplicate
  // observers if scanIframesIn() and the load-handler both call this).
  const watchedDocs = new WeakSet();
  function watchDocument(doc) {
    if (!doc || watchedDocs.has(doc) || !doc.body) return;
    watchedDocs.add(doc);
    const observer = new MutationObserver((records) => {
      for (const rec of records) {
        for (const node of rec.addedNodes) {
          if (node.nodeType === 1) {
            // New element — scan it (recurses into nested iframes)
            scanForSignatures(node);
            // If the new element IS an iframe (e.g. mail viewer creating
            // a new iframe per opened message), hook it explicitly
            if (node.tagName === 'IFRAME') {
              scanIframesIn(node);
            }
          } else if (node.nodeType === 3 && node.textContent.includes('#hhttps:')) {
            processTextNode(node);
          }
        }
      }
    });
    observer.observe(doc.body, { childList: true, subtree: true });
  }

  // ─── Signature insertion (context menu → signing flow) ───────────────────
  document.addEventListener('focusin', (e) => {
    const t = e.target;
    if (!t) return;
    if (t.tagName === 'TEXTAREA' || t.tagName === 'INPUT' ||
        (t.getAttribute && t.getAttribute('contenteditable') === 'true')) {
      lastFocusedEditable = t;
    }
  }, true);

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.type === 'REQUEST_TEXT_FOR_SIGN') {
      const text = getCurrentEditableText();
      const domain = getCurrentDomain();
      if (!text || !text.trim()) {
        flashError(chrome.i18n.getMessage('flashEnterTextFirst'));
        sendResponse({ ok: false });
        return;
      }
      chrome.runtime.sendMessage({
        type: 'SIGN_REQUEST',
        text,
        domain,
        mode: msg.mode || 'alpha'
      });
      sendResponse({ ok: true });
      return;
    }
    if (msg.type === 'INSERT_SIGNATURE' && msg.marker) {
      insertIntoFocused(msg.marker);
      sendResponse({ ok: true });
      return;
    }
    if (msg.type === 'SIGN_ERROR') {
      flashError(msg.error || chrome.i18n.getMessage('flashSigningFailed'));
      sendResponse({ ok: true });
      return;
    }
    if (msg.type === 'GET_PAGE_STATE') {
      const meta = readMetaTags();
      const base = meta.status ? meta : (lastReportedSig ? JSON.parse(lastReportedSig) : { status: 'none' });
      sendResponse({
        ...base,
        human: base.human === 'true' || base.human === true,
        trustScore: parseInt(base.trustScore || '0'),
        sealCount: scanCount.slug + scanCount.legacy
      });
    }
  });

  function getCurrentEditableText() {
    const el = lastFocusedEditable || document.activeElement;
    if (!el) return '';
    if (el.tagName === 'TEXTAREA' || el.tagName === 'INPUT') return el.value || '';
    if (el.getAttribute && el.getAttribute('contenteditable') === 'true') {
      return el.innerText || el.textContent || '';
    }
    return '';
  }

  function insertIntoFocused(marker) {
    const el = lastFocusedEditable || document.activeElement;
    if (!el) {
      flashError(chrome.i18n.getMessage('flashClickFieldFirst'));
      return;
    }
    if (el.tagName === 'TEXTAREA' || el.tagName === 'INPUT') {
      const cur = el.value || '';
      const sep = cur && !cur.endsWith(' ') && !cur.endsWith('\n') ? ' ' : '';
      el.value = cur + sep + marker;
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.focus();
    } else if (el.getAttribute && el.getAttribute('contenteditable') === 'true') {
      el.focus();
      const sel = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(el);
      range.collapse(false);
      sel.removeAllRanges();
      sel.addRange(range);
      document.execCommand('insertText', false, ' ' + marker);
    }
    flashSuccess(chrome.i18n.getMessage('flashInserted'));
  }

  function flashSuccess(msg) {
    const t = document.createElement('div');
    t.style.cssText = `
      position: fixed; bottom: 20px; right: 20px;
      background: linear-gradient(135deg, #5BAF6B, #889982);
      color: #FCFAF5; padding: 12px 18px;
      border-radius: 100px;
      font-family: -apple-system, system-ui, sans-serif;
      font-size: 13px; font-weight: 500;
      box-shadow: 0 8px 24px rgba(45,40,35,0.2);
      z-index: 2147483647;
      animation: hh-fade-in 0.3s;
    `;
    t.textContent = '✓ ' + msg;
    document.body.appendChild(t);
    setTimeout(() => { t.style.opacity = '0'; t.style.transition = 'opacity 0.4s'; }, 2200);
    setTimeout(() => t.remove(), 2700);
  }

  function flashError(msg) {
    const t = document.createElement('div');
    t.style.cssText = `
      position: fixed; bottom: 20px; right: 20px;
      background: #C97D5B; color: #FCFAF5;
      padding: 12px 18px; border-radius: 100px;
      font-family: -apple-system, system-ui, sans-serif;
      font-size: 13px; font-weight: 500;
      box-shadow: 0 8px 24px rgba(45,40,35,0.2);
      z-index: 2147483647;
    `;
    t.textContent = '⚠ ' + msg;
    document.body.appendChild(t);
    setTimeout(() => t.remove(), 3500);
  }

  // ─── Fetch/XHR header sniffer (passive) ──────────────────────────────────
  function extractHeaders(getter) {
    return {
      status: getter('HHTTPS-Status'), human: getter('HHTTPS-Human'),
      role: getter('HHTTPS-Role'), roleLabel: getter('HHTTPS-Role-Label'),
      roleIcon: getter('HHTTPS-Role-Icon'),
      trustScore: getter('HHTTPS-Trust-Score'),
      method: getter('HHTTPS-Method'), issuer: getter('HHTTPS-Issuer'),
      version: getter('HHTTPS-Protocol-Version')
    };
  }
  const origFetch = window.fetch;
  if (origFetch) {
    window.fetch = async function (...args) {
      const r = await origFetch.apply(this, args);
      try {
        const c = r.clone();
        const state = extractHeaders(h => c.headers.get(h));
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
        const state = extractHeaders(h => this.getResponseHeader(h));
        if (state.status) reportPageState(state);
      } catch (e) {}
    });
    return origSend.apply(this, args);
  };

  // ─── Boot ────────────────────────────────────────────────────────────────
  function boot() {
    injectStyles();
    const meta = readMetaTags();
    if (meta.status) reportPageState(meta);
    if (document.body) scanForSignatures(document.body);
    watchMutations();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
