/**
 * <iamhmn-card-issuer> — the "create a role yourself" UI (v0.5).
 *
 * This is the ISSUANCE surface: the user picks an occupation (ESCO typeahead) or
 * defines one freely, optionally attaches a document, and HHTTPS issues an
 * iamhmn-card into their wallet. Honest RAL:
 *   • no document      → RAL0 (self-declared)
 *   • document         → RAL1 (accredited; pilot: self-asserted)
 *   • reserved + RAL0  → refused by the server (needs a document or a qualified
 *                        external attestation) — the credibility gate.
 *
 * It does NOT replace the binary human/bot surface — it is the optional role step
 * after a human is verified. On success it emits `card-offer` with the wallet
 * offer URI; the host page renders the QR with its existing renderer (the same
 * one the EUDI age flow uses), so there is no new QR dependency here.
 *
 * Attributes: base (API base, default ""), session-id, locale ("de"|"en").
 * Events: card-offer { uri, crossDeviceUri, ral, role } · card-error { error }
 */

const RESERVED_STEMS = ['arzt','aerztin','dr. med','dr.med','drmed','physician','doctor','mediziner','chirurg','psychiater','approbation','anwalt','anwaelt','attorney','lawyer','advokat','notar','notary','polizei','polizist','police','kriminalbeamt','staatsanwalt','prosecutor','pfleger','pflegerin','pflegekraft','krankenpfleg','krankenschwester','nurse','altenpfleg','richter','judge'];
const fold = s => String(s||'').toLowerCase().replace(/ä/g,'ae').replace(/ö/g,'oe').replace(/ü/g,'ue').replace(/ß/g,'ss').replace(/\s+/g,' ').trim();
const reservedHit = s => { const n=fold(s); return RESERVED_STEMS.find(st=>n.includes(st))||null; };

const T = {
  de: {
    label: 'Welche Rolle möchtest du in dein Wallet laden?',
    ph: 'Beruf suchen (z. B. Tischler) oder frei eingeben …',
    doc: 'Nachweis-Dokument anhängen (optional, hebt auf RAL 1)',
    issue: 'Karte erstellen & ins Wallet laden',
    reservedWarn: 'Geschützter Beruf. Selbstangabe (RAL 0) ist nicht möglich — hänge ein Dokument an (RAL 1) oder zeige ein qualifiziertes Attestat (RAL 2).',
    ral0: 'Selbst angegeben (RAL 0) · von keiner Stelle geprüft',
    ral1: 'Mit Dokument (RAL 1) · im Pilot Selbstangabe, live gegen Register geprüft',
    ready: 'Karte bereit — im Wallet öffnen:',
    open: 'Im Wallet öffnen',
    err: 'Konnte die Karte nicht erstellen.'
  },
  en: {
    label: 'Which role do you want to load into your wallet?',
    ph: 'Search a profession (e.g. carpenter) or type freely …',
    doc: 'Attach a supporting document (optional, raises to RAL 1)',
    issue: 'Create card & load into wallet',
    reservedWarn: 'Protected profession. Self-declaration (RAL 0) is not allowed — attach a document (RAL 1) or present a qualified attestation (RAL 2).',
    ral0: 'Self-declared (RAL 0) · not checked by any authority',
    ral1: 'With document (RAL 1) · pilot: self-asserted, verified against registers in production',
    ready: 'Card ready — open in your wallet:',
    open: 'Open in wallet',
    err: 'Could not create the card.'
  }
};

const STYLE = `
  :host { --c-bg:#fff; --c-fg:#102a3c; --c-muted:#5b7080; --c-border:#cdd8e0;
          --c-accent:#00a3b4; --c-ral0:#9ca3af; --c-ral1:#2563eb; --c-warn:#b45309;
          font-family:inherit; color:var(--c-fg); display:block; }
  * { box-sizing:border-box; }
  .card { border:1px solid var(--c-border); border-radius:14px; padding:1.1rem 1.2rem; background:var(--c-bg); }
  label { display:block; font-size:.82rem; color:var(--c-muted); margin:0 0 .4rem; }
  input[type=text] { width:100%; padding:.6rem .7rem; font:inherit; color:inherit;
          background:var(--c-bg); border:1px solid var(--c-border); border-radius:9px; }
  input:focus { outline:2px solid var(--c-accent); outline-offset:1px; }
  .sug { position:relative; }
  .sug-list { position:absolute; left:0; right:0; top:calc(100% + 4px); z-index:20; background:var(--c-bg);
          border:1px solid var(--c-border); border-radius:9px; box-shadow:0 8px 24px rgba(16,42,60,.12);
          max-height:240px; overflow:auto; }
  .sug-item { padding:.5rem .7rem; cursor:pointer; display:flex; gap:.5rem; align-items:center; font-size:.9rem; }
  .sug-item:hover, .sug-item.active { background:rgba(0,163,180,.08); }
  .sug-item .isco { margin-left:auto; font-size:.7rem; color:var(--c-muted); }
  .sug-item .lock { color:var(--c-warn); }
  .docrow { display:flex; align-items:center; gap:.5rem; margin:.8rem 0 .2rem; font-size:.85rem; color:var(--c-muted); }
  button.issue { margin-top:1rem; width:100%; padding:.7rem; font:inherit; font-weight:600; cursor:pointer;
          color:#fff; background:var(--c-accent); border:none; border-radius:9px; }
  button.issue:disabled { opacity:.5; cursor:not-allowed; }
  .warn { color:var(--c-warn); font-size:.82rem; margin:.5rem 0 0; line-height:1.4; }
  .badge { display:inline-flex; align-items:center; gap:.5rem; padding:.4rem .7rem; border-radius:999px;
          font-size:.82rem; font-weight:600; margin-top:.9rem; border:1.5px solid; }
  .badge .dot { width:.7rem; height:.7rem; border-radius:50%; flex:none; }
  .badge.ral-0 { border-color:var(--c-ral0); color:var(--c-ral0); }
  .badge.ral-0 .dot { border:2px solid var(--c-ral0); }
  .badge.ral-1 { border-color:var(--c-ral1); color:var(--c-ral1); background:rgba(37,99,235,.08); }
  .badge.ral-1 .dot { background:var(--c-ral1); }
  .openbtn { display:inline-block; margin-top:.7rem; padding:.55rem .9rem; border-radius:9px;
          background:var(--c-fg); color:#fff; text-decoration:none; font-size:.85rem; }
  .ready { margin-top:.6rem; font-size:.85rem; color:var(--c-muted); }
`;

class IamhmnCardIssuer extends HTMLElement {
  constructor() { super(); this._sel = null; this._docs = false; this._sug = []; this._active = -1;
    this.attachShadow({ mode: 'open' }); }
  get base() { return this.getAttribute('base') || ''; }
  get sessionId() { return this.getAttribute('session-id') || ''; }
  get locale() { return this.getAttribute('locale') === 'en' ? 'en' : 'de'; }
  get t() { return T[this.locale]; }

  connectedCallback() { this._render(); }

  _render() {
    const t = this.t;
    this.shadowRoot.innerHTML = `
      <style>${STYLE}</style>
      <div class="card">
        <label for="q">${t.label}</label>
        <div class="sug">
          <input id="q" type="text" autocomplete="off" placeholder="${t.ph}" maxlength="64" />
          <div class="sug-list" id="list" hidden></div>
        </div>
        <div class="docrow">
          <input type="checkbox" id="doc" /><label for="doc" style="margin:0;cursor:pointer;">${t.doc}</label>
        </div>
        <p class="warn" id="warn" hidden></p>
        <button class="issue" id="go" type="button" disabled>${t.issue}</button>
        <div id="result"></div>
      </div>`;

    const q = this.shadowRoot.querySelector('#q');
    const list = this.shadowRoot.querySelector('#list');
    const doc = this.shadowRoot.querySelector('#doc');
    const go = this.shadowRoot.querySelector('#go');

    let timer = null;
    q.addEventListener('input', () => {
      this._sel = null;
      clearTimeout(timer);
      timer = setTimeout(() => this._suggest(q.value.trim()), 180);
      this._refresh();
    });
    q.addEventListener('keydown', (e) => this._nav(e));
    doc.addEventListener('change', () => { this._docs = doc.checked; this._refresh(); });
    go.addEventListener('click', () => this._issue());
    document.addEventListener('click', (e) => { if (!this.contains(e.target)) this._hideList(); });
  }

  async _suggest(text) {
    if (text.length < 2) { this._sug = []; this._renderList(); return; }
    try {
      const r = await fetch(`${this.base}/hhttps/esco/suggest?q=${encodeURIComponent(text)}&lang=${this.locale}`,
        { headers: { accept: 'application/json' } });
      const j = await r.json();
      this._sug = Array.isArray(j.results) ? j.results : [];
    } catch { this._sug = []; }
    this._active = -1;
    this._renderList();
  }

  _renderList() {
    const list = this.shadowRoot.querySelector('#list');
    if (!this._sug.length) { list.hidden = true; list.innerHTML = ''; return; }
    list.innerHTML = this._sug.map((s, i) =>
      `<div class="sug-item ${i === this._active ? 'active' : ''}" data-i="${i}">
        ${s.reserved ? '<span class="lock">🔒</span>' : ''}
        <span>${this._esc(s.label)}</span>
        ${s.isco08 ? `<span class="isco">ISCO ${this._esc(s.isco08)}</span>` : ''}
      </div>`).join('');
    list.hidden = false;
    list.querySelectorAll('.sug-item').forEach(el =>
      el.addEventListener('click', () => this._pick(this._sug[Number(el.dataset.i)])));
  }

  _hideList() { const l = this.shadowRoot.querySelector('#list'); if (l) l.hidden = true; }

  _nav(e) {
    if (this._sug.length && (e.key === 'ArrowDown' || e.key === 'ArrowUp')) {
      e.preventDefault();
      this._active = (this._active + (e.key === 'ArrowDown' ? 1 : -1) + this._sug.length) % this._sug.length;
      this._renderList();
    } else if (e.key === 'Enter' && this._active >= 0) {
      e.preventDefault(); this._pick(this._sug[this._active]);
    }
  }

  _pick(s) {
    this._sel = s;
    this.shadowRoot.querySelector('#q').value = s.label;
    this._hideList();
    this._refresh();
  }

  _refresh() {
    const t = this.t;
    const q = this.shadowRoot.querySelector('#q').value.trim();
    const warn = this.shadowRoot.querySelector('#warn');
    const go = this.shadowRoot.querySelector('#go');
    // reserved? from the picked ESCO hit, or a client-side stem check on free text.
    const reserved = this._sel ? this._sel.reserved : !!reservedHit(q);
    if (reserved && !this._docs) {
      warn.textContent = t.reservedWarn; warn.hidden = false; go.disabled = true; return;
    }
    warn.hidden = true;
    go.disabled = q.length < 2;
  }

  async _issue() {
    const t = this.t;
    const q = this.shadowRoot.querySelector('#q').value.trim();
    const go = this.shadowRoot.querySelector('#go');
    go.disabled = true;

    const body = { sessionId: this.sessionId, documentProvided: this._docs };
    if (this._sel) body.esco = { label: this._sel.label, isco08: this._sel.isco08, escoUri: this._sel.escoUri };
    else body.customRole = q;

    let d;
    try {
      const r = await fetch(`${this.base}/hhttps/role/card`, {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body)
      });
      d = await r.json();
      if (!r.ok) {
        this.shadowRoot.querySelector('#warn').textContent = d.remedy || d.error || t.err;
        this.shadowRoot.querySelector('#warn').hidden = false;
        this.dispatchEvent(new CustomEvent('card-error', { bubbles: true, composed: true, detail: { error: d.error } }));
        go.disabled = false; return;
      }
    } catch (e) {
      this.dispatchEvent(new CustomEvent('card-error', { bubbles: true, composed: true, detail: { error: String(e) } }));
      go.disabled = false; return;
    }

    const ral = d.card?.ral ?? 0;
    const uri = d.offer?.uri;
    this.shadowRoot.querySelector('#result').innerHTML = `
      <div class="badge ral-${ral}"><span class="dot"></span><span>${ral === 1 ? t.ral1 : t.ral0}</span></div>
      <div class="ready">${t.ready}</div>
      ${uri ? `<a class="openbtn" href="${this._esc(uri)}">${t.open}</a>` : ''}`;
    // Host page renders the QR for cross-device using its existing renderer.
    this.dispatchEvent(new CustomEvent('card-offer', {
      bubbles: true, composed: true,
      detail: { uri, crossDeviceUri: d.offer?.crossDeviceUri || uri, ral, role: d.card?.role || null }
    }));
    go.disabled = false;
  }

  _esc(s) { return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
}

customElements.define('iamhmn-card-issuer', IamhmnCardIssuer);
export { IamhmnCardIssuer };
