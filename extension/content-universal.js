/**
 * HHTTPS Extension — Universal Content Script
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

  // AP8-22 (#249): the content script used to log slug lists and page details
  // into every visited page's console. Set `localStorage.hhttpsDebug = '1'` on
  // a page to get them back while debugging.
  const DEBUG = (() => {
    try { return localStorage.getItem('hhttpsDebug') === '1'; } catch (e) { return false; }
  })();
  const debug = (...a) => { if (DEBUG) console.log('[HHTTPS]', ...a); };

  // ─── Instance marker (AP8-24) ────────────────────────────────────────────
  // The manifest injects this script into EVERY frame (all_frames +
  // match_about_blank), so a same-origin iframe normally has its own instance
  // with its own scanner, observer and slug cache. The parent instance used to
  // hook the same contentDocument as well, which doubled the DOM work and the
  // POST /hhttps/signatures/batch requests per frame (× nesting depth).
  //
  // Chosen fix: keep all_frames (it is the only way to reach cross-origin and
  // sandboxed frames) and keep the parent-side iframe hooks ONLY as a fallback
  // for frames that have no instance of their own (initial about:blank
  // documents Chrome does not inject into, document.write()-replaced documents,
  // frames created before the parent's instance booted …). Each instance stamps
  // its own <html> with a DOM attribute — attributes are visible across the
  // per-frame isolated worlds, JS expandos are not — and the parent skips or
  // disconnects from any frame document that carries it. A replaced document
  // gets a fresh <html> without the stamp, so the fallback re-engages there
  // until the new instance boots. This was preferred over dropping all_frames
  // (loses cross-origin frames) or a postMessage handshake (async, page-visible).
  const INSTANCE_ATTR = 'data-hhttps-instance';
  function markOwnInstance() {
    try { document.documentElement?.setAttribute(INSTANCE_ATTR, '1'); } catch (e) {}
  }
  markOwnInstance();
  // A frame document that already has a content-script instance of its own.
  function hasOwnInstance(doc) {
    try { return !!doc?.documentElement?.hasAttribute(INSTANCE_ATTR); } catch (e) { return false; }
  }

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
  // AP8-27 (#206): a failed batch verify is cached too, but only briefly —
  // long enough to stop every scan from re-sending the same doomed request,
  // short enough to recover quickly once the server is reachable again.
  const ERROR_TTL = 30_000;

  // Track scans for popup stats
  let scanCount = { slug: 0, legacy: 0 };
  let lastFocusedEditable = null;

  // ─── Page state reading ──────────────────────────────────────────────────
  // AP8-45 (#240): the state used to be pushed to the service worker as
  // PAGE_STATE and cached there per tab — which nothing read, because the
  // popup asks this tab directly (GET_PAGE_STATE). It is kept here instead.
  // The fetch/XHR header sniffer that used to feed it was removed with it: a
  // content script lives in the isolated world and never sees the page's own
  // requests, so it only ever observed our own fetch.
  // AP8-19 (#167): what is left comes from the page's <meta> tags, which is a
  // CLAIM (claimed: true) and must be rendered as such by the popup.
  let pageState = null;
  function setPageState(state) {
    if (!state || !state.status) return;
    pageState = state;
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
      issuer: m('issuer'), version: m('version'),
      // AP8-19 (#167): <meta name="hhttps-*"> lives in the page DOM. Anyone
      // who can put markup on the page — including a user-generated comment —
      // can write `verified` there. The value is passed on as a CLAIM, never
      // as a verification, and the popup renders it neutrally.
      source: 'meta', claimed: true
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
      if (!cached || (Date.now() - cached.fetchedAt) > (cached.ttl || CACHE_TTL)) {
        slugsToFetch.push(slug);
      }
    }
    if (slugs.size > 0) {
      debug('found slugs to verify:', slugs.size, '· to fetch:', slugsToFetch.length);
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
        // AP8-25 (#194): the text check is a substring scan on a string we
        // already hold; the two closest() calls walk the ancestor chain. The
        // overwhelming majority of text nodes carry no marker at all, so the
        // cheap check runs FIRST and the DOM walks only for real candidates.
        const t = node.textContent;
        if (!t || (!t.includes('#hhttps:s:') &&
                   !t.includes('#hhttps:a:') &&
                   !t.includes('#hhttps:b:'))) return NodeFilter.FILTER_REJECT;
        if (!node.parentElement) return NodeFilter.FILTER_REJECT;
        if (SKIP_TAGS.has(node.parentElement.tagName)) return NodeFilter.FILTER_REJECT;
        if (node.parentElement.closest(`.${SEAL_WRAPPER}`)) return NodeFilter.FILTER_REJECT;
        if (node.parentElement.closest('[contenteditable="true"]')) return NodeFilter.FILTER_REJECT;
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
  // MutationObserver, AND (only while the body is still empty) poll for late
  // content with exponential backoff.
  //
  // All of this is a FALLBACK: frames that run their own instance of this
  // script (see INSTANCE_ATTR) are left alone entirely (AP8-24).
  const iframesHooked = new WeakSet();
  const IFRAME_POLL_INITIAL_MS = 500;      // 0.5 s → 1 s → 2 s → 4 s → 8 s → 16 s
  const IFRAME_POLL_MAX_MS     = 16_000;
  const IFRAME_POLL_MAX_ATTEMPTS = 6;      // ≈ 31.5 s total, 6 checks (was 20 × 1.5 s)

  function scanIframesIn(root) {
    const iframes = root.nodeType === 1 && root.tagName === 'IFRAME'
      ? [root]
      : Array.from(root.querySelectorAll ? root.querySelectorAll('iframe') : []);

    for (const iframe of iframes) {
      tryHookIframe(iframe);
    }
  }

  // Cheap emptiness check — never serialise innerHTML (AP8-23).
  function bodyHasContent(doc) {
    const body = doc && doc.body;
    return !!body && (body.childElementCount > 0 || body.childNodes.length > 0);
  }

  // Process a reachable frame document once: styles + scan + observer.
  // Returns false when the frame has its own instance (nothing to do here).
  function processFrameDocument(doc) {
    if (!doc || hasOwnInstance(doc)) return false;
    try {
      injectStylesInto(doc);
      if (doc.body) { scanForSignatures(doc.body); watchDocument(doc); }
    } catch (e) {}
    return true;
  }

  function tryHookIframe(iframe) {
    let doc;
    try {
      doc = iframe.contentDocument;
    } catch (e) {
      return;  // Cross-origin — silently skip
    }
    if (!doc) return;

    // Frame runs its own content-script instance → it scans itself (AP8-24).
    if (hasOwnInstance(doc)) return;

    // (Re)scan now — the frame content may have changed since we hooked it.
    processFrameDocument(doc);

    // First time we see this iframe? Set up persistent watchers.
    if (iframesHooked.has(iframe)) return;
    iframesHooked.add(iframe);

    const onFrameChange = () => {
      try { processFrameDocument(iframe.contentDocument); } catch (e) {}
    };

    // Hook 1: load event (works for src= iframes)
    iframe.addEventListener('load', onFrameChange);

    // Hook 2: MutationObserver on iframe element (catches srcdoc changes)
    try {
      const attrObserver = new MutationObserver(onFrameChange);
      attrObserver.observe(iframe, { attributes: true, attributeFilter: ['src', 'srcdoc'] });
    } catch (e) {}

    // Hook 3: body observer is attached by processFrameDocument() above; if the
    // body is not there yet, defer to DOMContentLoaded.
    if (!doc.body) {
      doc.addEventListener?.('DOMContentLoaded', onFrameChange);
    }

    // Hook 4: polling fallback for the worst-case async writers — only when
    // there is nothing in the body yet, with exponential backoff, and it stops
    // as soon as the body observer is in place / content appeared / the frame
    // got its own instance / the frame left the DOM (AP8-23).
    if (bodyHasContent(doc)) return;
    let attempts = 0;
    let delay = IFRAME_POLL_INITIAL_MS;
    const poll = () => {
      attempts++;
      let stillThere = false;
      try { stillThere = document.contains(iframe); } catch (e) {}
      if (!stillThere) return;
      let d = null;
      try { d = iframe.contentDocument; } catch (e) { return; }
      if (!d || hasOwnInstance(d)) return;
      if (watchedDocs.has(d) && d.body && d.body.isConnected) return;  // observer active
      if (bodyHasContent(d)) { processFrameDocument(d); return; }
      if (attempts >= IFRAME_POLL_MAX_ATTEMPTS) return;
      delay = Math.min(delay * 2, IFRAME_POLL_MAX_MS);
      setTimeout(poll, delay);
    };
    setTimeout(poll, delay);
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
  // Every document a seal can live in: the main one plus every iframe we can
  // reach (cross-origin frames throw and are skipped).
  function sealDocuments() {
    const docs = [document];
    try {
      for (const iframe of document.querySelectorAll('iframe')) {
        try { if (iframe.contentDocument) docs.push(iframe.contentDocument); }
        catch (e) { /* cross-origin */ }
      }
    } catch (e) {}
    return docs;
  }

  // AP8-27 (#206): remember that these slugs could not be verified and take
  // their seals out of the endless `pending` state.
  function cacheFailure(slugs) {
    for (const slug of slugs) {
      if (slugCache.has(slug) && !slugCache.get(slug).error) continue;  // keep a good result
      slugCache.set(slug, { data: null, error: true, fetchedAt: Date.now(), ttl: ERROR_TTL });
      for (const doc of sealDocuments()) {
        doc.querySelectorAll(`.${SEAL_CLASS}[data-slug="${slug}"]`).forEach(renderSealUnavailable);
      }
    }
  }

  // AP8-27 (#206): the server was unreachable — this is explicitly NOT a
  // verdict on the signature, so the seal must not read as invalid.
  function renderSealUnavailable(sealEl) {
    sealEl.setAttribute('data-state', 'unavailable');
    sealEl.innerHTML = '<span class="hh-seal-icon">\u2014</span><span class="hh-seal-label"></span>';
    sealEl.querySelector('.hh-seal-label').textContent = chrome.i18n.getMessage('sealUnavailable');
    sealEl.setAttribute('title', chrome.i18n.getMessage('sealUnavailableTitle'));
  }

  // AP8-27 (#206): the server refuses more than 100 slugs per request
  // (400 `too many slugs`), so the list is split into chunks of at most
  // BATCH_MAX. Every chunk is fetched on its own; one failing chunk does not
  // take the others down with it.
  const BATCH_MAX = 100;
  async function batchVerifySlugs(slugs) {
    const list = Array.from(new Set(slugs));
    if (list.length <= BATCH_MAX) return batchVerifyChunk(list);
    const chunks = [];
    for (let i = 0; i < list.length; i += BATCH_MAX) chunks.push(list.slice(i, i + BATCH_MAX));
    const done = await Promise.allSettled(chunks.map((c) => batchVerifyChunk(c)));
    const failed = done.find((d) => d.status === 'rejected');
    if (failed) throw failed.reason;
  }

  async function batchVerifyChunk(slugs) {
    const domain = getCurrentDomain();
    if (!domain) return;
    if (!slugs.length) return;

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
        // AP8-27 (#206): without a cache entry the seals stay `pending`
        // forever and every later scan re-sends the same failing request.
        // A short negative entry makes the seal show `unknown` and lets the
        // next scan retry after ERROR_TTL.
        cacheFailure(slugs);
        return;
      }
      const data = await r.json();
      const results = data.results || {};
      debug('batch verify response:', Object.keys(results).length, 'results');
      for (const [slug, result] of Object.entries(results)) {
        slugCache.set(slug, { data: result, fetchedAt: Date.now() });
        // Update pending seals in main doc AND in accessible iframes
        for (const doc of sealDocuments()) {
          doc.querySelectorAll(`.${SEAL_CLASS}[data-slug="${slug}"]`).forEach(seal => {
            renderSealFromBatchResult(seal, result);
          });
        }
      }
      // Slugs the server did not answer for at all: also take them out of
      // `pending` so the seal does not spin forever (AP8-27 / #206).
      cacheFailure(slugs.filter((sl) => !results[sl]));
    } catch (e) {
      console.warn('[HHTTPS] batch verify failed:', e);
      cacheFailure(slugs);
    }
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
      return d.toLocaleDateString(chrome.i18n.getUILanguage(), { day: '2-digit', month: 'short', year: 'numeric' });
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
      .${SEAL_CLASS}[data-state="unavailable"] {
        background: #F3F3F1; color: #6B6B66; border-color: #D8D8D2;
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
    if (doc !== document && hasOwnInstance(doc)) return;   // AP8-24
    watchedDocs.add(doc);

    // AP8-26 (#201): mutations are COLLECTED, not processed inline. A chatty
    // page (infinite scroll, a mail client re-rendering a thread) delivers
    // hundreds of addedNodes per second, and every element used to trigger a
    // full scanForSignatures() — including querySelectorAll('iframe') and a
    // TreeWalker — synchronously inside the observer callback. Now the nodes
    // are queued and drained once, in an idle slot.
    //
    // Our own seal wrappers are skipped before they enter the queue: writing
    // them re-triggers the observer, and re-scanning them can never find
    // anything (the walker rejects everything under SEAL_WRAPPER anyway).
    let pending = [];
    let drainHandle = null;
    const idle = (fn) => (typeof requestIdleCallback === 'function'
      ? requestIdleCallback(fn, { timeout: 500 })
      : setTimeout(fn, 100));

    function isOwnSealNode(node) {
      try {
        if (node.nodeType === 1) {
          return node.classList?.contains(SEAL_WRAPPER)
              || node.classList?.contains(SEAL_CLASS)
              || !!node.closest?.(`.${SEAL_WRAPPER}`);
        }
        return !!node.parentElement?.closest?.(`.${SEAL_WRAPPER}`);
      } catch (e) { return false; }
    }

    function drain() {
      drainHandle = null;
      const batch = pending;
      pending = [];
      for (const node of batch) {
        if (!node.isConnected) continue;
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

    const observer = new MutationObserver((records) => {
      // A frame document we hooked as a fallback got its own instance in the
      // meantime → hand over and stop duplicating its work (AP8-24).
      if (doc !== document && hasOwnInstance(doc)) {
        observer.disconnect();
        watchedDocs.delete(doc);
        pending = [];
        return;
      }
      for (const rec of records) {
        for (const node of rec.addedNodes) {
          if (node.nodeType !== 1 && node.nodeType !== 3) continue;
          if (isOwnSealNode(node)) continue;
          pending.push(node);
        }
      }
      if (pending.length && drainHandle === null) drainHandle = idle(drain);
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
      // AP8-19 (#167): the header-derived state (from the origin's server)
      // wins over the page's own <meta> tags — the meta tags used to be
      // preferred, so a page could overrule its own server.
      const meta = readMetaTags();
      const base = (pageState && pageState.status) ? pageState
                 : (meta.status ? meta : { status: 'none' });
      sendResponse({
        ...base,
        human: base.human === 'true' || base.human === true,
        trustScore: parseInt(base.trustScore || '0'),
        claimed: base.claimed !== false,
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

  // ─── Boot ────────────────────────────────────────────────────────────────
  function boot() {
    markOwnInstance();
    injectStyles();
    const meta = readMetaTags();
    if (meta.status) setPageState(meta);
    if (document.body) scanForSignatures(document.body);
    watchMutations();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
