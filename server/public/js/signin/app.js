/* iamhmn sign-in — World-ID-inspired. EMAIL FIRST, then the other methods:
   the confirmed e-mail is the identity anchor (AK-14); passkey, EUDI, GitHub
   and age stay disabled until it is confirmed. The machine path is separate.
   CREDIBILITY RULE: a method is marked "confirmed" only after it REALLY
   completes against the server. Completing one OFFERS the others — never
   auto-credits them. The trust score is never shown (API/token only).

   AP8-34 (#215): this used to be a 675-line inline <script> in index.html
   that could only be tested with regexes over the HTML. It is now an ES
   module served as a static asset, with the pure parts split into i18n.js,
   identity.js, poll.js and util.js so the unit tests import and call them.
   Every `onclick=` attribute was replaced by an addEventListener wiring in
   bindEvents(), so the page no longer needs `script-src-attr 'unsafe-inline'`. */

import { tr as trIn } from './i18n.js';
import {
  STORAGE_KEY, buildIdentity, buildMachineIdentity,
  storableRefreshToken, resolveReturnTo
} from './identity.js';
import { createPoller } from './poll.js';
import { escHtml, shortToken, jwtExp, normaliseCode, isEmail } from './util.js';

const API = '';
let sessionId = null;
let LANG = (localStorage.getItem('iamhmn-lang') || 'de');
const confirmed = { email: false, passkey: false, eudi: false, github: false, machine: false, age: false };
const ORDER = ['email', 'passkey', 'eudi', 'github'];
const PANELS = ['email', 'passkey', 'eudi', 'github', 'machine', 'age'];

const $ = (id) => document.getElementById(id);
const tr = (k) => trIn(LANG, k);
/** Confirmed human methods, in ORDER. */
const methodsOf = () => ORDER.filter((m) => confirmed[m]);
const setText = (id, k) => { const el = $(id); if (el) el.textContent = tr(k); };
const jsonPost = (path, body) => fetch(API + path, {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body)
});

const poller = createPoller();

// ── i18n ────────────────────────────────────────────────────────────────────
function applyLang() {
  document.documentElement.lang = LANG;
  $('langBtn').textContent = LANG === 'de' ? 'EN' : 'DE';
  document.querySelectorAll('[data-i18n]').forEach((el) => { el.textContent = tr(el.getAttribute('data-i18n')); });
  document.querySelector('.hero h1').innerHTML = escHtml(tr('hero.a')) + ' <span class="em">' + escHtml(tr('hero.em')) + '</span>' + escHtml(tr('hero.b'));
  const ph = { machineRole: 'machine.role.ph', pseudoInput: 'email.pseudo.ph',
               machineEmail: 'machine.email.ph', escoInput: 'role.search.ph' };
  for (const id of Object.keys(ph)) { const el = $(id); if (el) el.placeholder = tr(ph[id]); }
  renderQualChips();
  renderProgress();
}
function toggleLang() {
  LANG = LANG === 'de' ? 'en' : 'de';
  localStorage.setItem('iamhmn-lang', LANG);
  applyLang();
}

// ── Method accordion ────────────────────────────────────────────────────────
function pick(m) {
  if (MACHINE_IDENTITY && m !== 'machine') { setText('machineHint', 'machine.locked'); return; }
  if (confirmed[m]) return;
  const btn = $('m-' + m);
  if (btn && btn.disabled) {
    /* AK-14: email first. The other human methods stay locked until the
       email is confirmed (the server enforces the same rule with 403). */
    setText('emailHint', 'email.first');
    return;
  }
  PANELS.forEach((x) => { const p = $('panel-' + x); if (p) p.classList.toggle('hidden', x !== m); });
  const f = document.querySelector('#panel-' + m + ' .field, #panel-' + m + ' .go');
  if (f) setTimeout(() => f.focus(), 60);
}
function renderProgress() {
  const n = methodsOf().length;
  const prog = $('progress'), ticks = $('ticks'), label = $('progressLabel');
  if (n === 0) { prog.classList.add('hidden'); return; }
  prog.classList.remove('hidden');
  label.textContent = n === 1 ? tr('progress.one') : (n + tr('progress.more'));
  ticks.innerHTML = ORDER.map((m) => `<span class="tick ${confirmed[m] ? 'on' : ''}"></span>`).join('');
}
function markConfirmed(m) {
  confirmed[m] = true;
  $('m-' + m).classList.add('done');
  $('panel-' + m)?.classList.add('hidden');
  $('st-' + m).innerHTML = '<span class="check"><svg viewBox="0 0 24 24" fill="none"><path d="m5 13 4 4L19 7" stroke="currentColor" stroke-width="2.4"/></svg></span>';
  $('issueBtn').disabled = false;
  if (m === 'email') unlockMethods();
  renderProgress();
}
/* AK-14: once the email is confirmed, enable every gated method button and
   drop the persistent "email first" hint. */
function unlockMethods() {
  document.querySelectorAll('[data-requires-email]').forEach((b) => { b.removeAttribute('disabled'); });
  const h = $('emailFirstHint'); if (h) h.hidden = true;
}
/** Pseudonym chip next to the e-mail check mark (AK-8/AK-15, display only). */
function showPseudonym(pseudonym) {
  if (!pseudonym) return;
  const st = $('st-email');
  const sp = document.createElement('span');
  sp.className = 'pseudo'; sp.textContent = pseudonym;
  st.appendChild(document.createTextNode(' ')); st.appendChild(sp);
}

/* ── Session bootstrap ─────────────────────────────────────────────────────
   Email is always first (AK-14). session/start mints a method-neutral session;
   every other method needs that session (and a confirmed email) to exist. */
let pkUserId = null;
async function ensureSession() {
  if (sessionId) return sessionId;
  const r = await jsonPost('/hhttps/session/start', {});
  const d = await r.json(); if (!r.ok) throw 0;
  sessionId = d.sessionId; return sessionId;
}

/* EMAIL — ensureSession -> email/send -> email/confirm-code */
async function emailStart() {
  const email = $('emailInput').value.trim();
  const hint = $('emailHint');
  if (!isEmail(email)) { hint.textContent = tr('err'); return; }
  try {
    await ensureSession();
    const pseudonym = ($('pseudoInput')?.value || '').trim();
    const r = await jsonPost('/hhttps/email/send', pseudonym ? { sessionId, email, pseudonym } : { sessionId, email });
    const d = await r.json(); if (!r.ok) throw 0;
    $('emailCodeRow').classList.remove('hidden');
    /* AP8-13 (#249): in EMAIL_DEV_MODE the server answers with the code
       itself; show it instead of pointing at an inbox that never fills. */
    hint.textContent = d.devCode ? tr('codeSent') + ' (dev: ' + d.devCode + ')' : tr('codeSent');
    $('emailCode').focus();
  } catch { hint.textContent = tr('err'); }
}
async function emailConfirm() {
  const code = normaliseCode($('emailCode').value);
  const hint = $('emailHint');
  try {
    const r = await jsonPost('/hhttps/email/confirm-code', { sessionId, code });
    const d = await r.json(); if (!r.ok) throw 0;
    markConfirmed('email');
    const pseudonym = (d.pseudonym || '').toString();
    if (pseudonym) {
      showPseudonym(pseudonym);
      hint.textContent = tr('email.done').replace('{p}', pseudonym);
    }
  } catch { hint.textContent = tr('err'); }
}

/* PASSKEY — register(start->finish) then auth(start->finish). auth/finish
   creates the session and merges our prior one via priorSessionId.
   K-4: a RETURNING user (same email => same stable userId) already has a
   credential; register/start then lists it in excludeCredentials and the
   authenticator would refuse with InvalidStateError. In that case we skip
   registration and go straight to auth/start. */
async function passkeyRun() {
  const hint = $('passkeyHint');
  const L = window.SimpleWebAuthnBrowser;
  if (!L) { hint.textContent = 'WebAuthn lib missing'; return; }
  try {
    await ensureSession();
    /* D4: the user handle is the session's stable userId; the server answers
       403 email_verification_required until the email is confirmed. */
    const rs = await jsonPost('/hhttps/webauthn/register/start', { sessionId });
    const ro = await rs.json(); if (!rs.ok) throw 0;
    pkUserId = ro.userId;
    const excl = (ro.options && ro.options.excludeCredentials) || [];
    let hasPasskey = excl.length > 0;
    if (!hasPasskey) {
      try {
        const regResp = await L.startRegistration(ro.options);
        const rf = await jsonPost('/hhttps/webauthn/register/finish', { userId: pkUserId, response: regResp, sessionId });
        if (!rf.ok) throw 0;
      } catch (e) {
        /* The authenticator already holds a credential for this user handle
           (e.g. registered on this device before the server knew about it). */
        if (e && e.name === 'InvalidStateError') hasPasskey = true; else throw e;
      }
    }
    if (hasPasskey) hint.textContent = tr('passkey.existing');
    const as = await jsonPost('/hhttps/webauthn/auth/start', { userId: pkUserId });
    const ao = await as.json(); if (!as.ok) throw 0;
    const authResp = await L.startAuthentication(ao.options);
    const af = await jsonPost('/hhttps/webauthn/auth/finish', { sessionId: ao.sessionId, response: authResp, priorSessionId: sessionId });
    const d = await af.json(); if (!af.ok) throw 0;
    sessionId = d.sessionId;
    markConfirmed('passkey');
  } catch { hint.textContent = tr('err'); }
}

/* EUDI — needs a session; eid/request -> poll eid/status/:requestId */
function showQr(deepLink, imgId, linkId, wrapId, rowId) {
  const qr = qrcode(0, 'L'); qr.addData(deepLink); qr.make();
  $(imgId).src = qr.createDataURL(4, 8);
  $(linkId).href = deepLink;
  $(wrapId).style.display = 'flex';
  $(rowId).style.display = 'none';
}
async function eudiRun() {
  const hint = $('eudiHint');
  try {
    await ensureSession();
    const r = await jsonPost('/eudi/eid/request', { hhttpsSession: sessionId });
    const d = await r.json(); if (!r.ok || !d.deepLink) throw 0;
    showQr(d.deepLink, 'eudiQr', 'eudiLink', 'eudiQrWrap', 'eudiStartRow');
    pollEudi(d.requestId);
  } catch { hint.textContent = tr('err'); }
}
async function pollEudi(requestId) {
  return poller.poll('eudi',
    () => fetch(API + '/eudi/eid/status/' + encodeURIComponent(requestId)),
    (d) => d.status === 'verified', () => markConfirmed('eudi'),
    (k) => setText('eudiHint', k));
}

/* AGE — equal 6th entry. Some users only want to prove their age. EUDI Wallet
   age_over_NN, minAge in {14,16,18}. Orthogonal & trust-neutral: confirming an
   age threshold does NOT mint a human token on its own (matches the backend). */
async function ageRun(minAge) {
  const hint = $('ageHint');
  try {
    await ensureSession();
    const r = await jsonPost('/eudi/age/request', { hhttpsSession: sessionId, minAge });
    const d = await r.json(); if (!r.ok || !d.deepLink) throw 0;
    showQr(d.deepLink, 'ageQr', 'ageLink', 'ageQrWrap', 'ageStartRow');
    hint.textContent = tr('age.waiting');
    pollAge(d.requestId, minAge);
  } catch { hint.textContent = tr('err'); }
}
async function pollAge(requestId, minAge) {
  return poller.poll('age',
    () => fetch(API + '/eudi/age/status/' + encodeURIComponent(requestId)),
    (d) => d.status === 'verified', () => ageConfirmed(minAge),
    (k) => setText('ageHint', k));
}
function ageConfirmed(minAge) {
  confirmed.age = true;
  $('m-age').classList.add('done');
  $('st-age').textContent = '✓ ' + minAge + '+';
  $('ageHint').textContent = tr('age.done').replace('{n}', minAge);
}

/* GITHUB — needs a session; popup verify/github/start?session=, poll status.
   AP8-14 (#249): the popup used to swallow a 503 github_not_configured as raw
   JSON while the page polled on in silence. /hhttps/verify/github/status
   answers 503 too, so the poller now ends the run with a readable hint. */
async function githubRun() {
  try {
    await ensureSession();
    window.open(API + '/hhttps/verify/github/start?session=' + encodeURIComponent(sessionId), '_blank', 'width=600,height=720');
    pollGithub();
  } catch { /* ensureSession already reported nothing to show here */ }
}
async function pollGithub() {
  return poller.poll('github',
    () => jsonPost('/hhttps/verify/github/status', { sessionId }),
    (d) => d.verified === true, () => markConfirmed('github'),
    (k) => setText('githubHint', k));
}

/* MACHINE — honest bot declaration -> machine apiKey (NOT a human token) */
let MACHINE_IDENTITY = false;
let MACHINE_STEP = 'email';

async function machineRun() {
  const role = $('machineRole').value.trim();
  const email = ($('machineEmail').value || '').trim();
  const hint = $('machineHint');
  if (!isEmail(email)) { hint.textContent = tr('machine.email.err'); return; }

  /* Step A: send the confirmation code to the operator e-mail. Reuses the
     human code-mail flow — confirmation only, ZERO trust for machines. */
  if (MACHINE_STEP === 'email') {
    try {
      await ensureSession();
      const rs = await jsonPost('/hhttps/email/send', { sessionId, email });
      if (!rs.ok) throw 0;
      MACHINE_STEP = 'code';
      $('machineCodeRow').classList.remove('hidden');
      $('machineEmail').readOnly = true;
      const gb = $('machineGo');
      if (gb) { gb.setAttribute('data-i18n', 'machine.go2'); gb.textContent = tr('machine.go2'); }
      hint.textContent = tr('machine.codeSent');
      $('machineCode').focus();
    } catch { hint.textContent = tr('err'); }
    return;
  }

  /* Step B: confirm the code ONCE (the server consumes it), then register +
     issue the machine token. AP8-06 (#90): after a successful confirm-code the
     step advances to 'confirmed', so a failing register/token call can simply
     be retried without re-sending the consumed code; the server's error
     detail is shown instead of the generic text. */
  if (MACHINE_STEP === 'code') {
    const code = normaliseCode($('machineCode').value);
    try {
      const rc = await jsonPost('/hhttps/email/confirm-code', { sessionId, code });
      if (!rc.ok) { hint.textContent = tr('machine.codeErr'); return; }
    } catch { hint.textContent = tr('err'); return; }
    MACHINE_STEP = 'confirmed';
    $('machineCodeRow')?.classList.add('hidden');
  }
  const machineErr = (d, r) => {
    const det = (d && (d.detail || d.error)) || '';
    hint.textContent = tr('err') + (det ? ' (' + det + (r && r.status === 429 ? ' · 429' : '') + ')' : '');
  };
  try {
    /* WIMSE preparation, in the background: generate a P-256 keypair and send
       the PUBLIC JWK with the registration. The server binds it in a later
       phase (cnf/jkt); today it is stored client-visible only. The PRIVATE
       JWK is shown once to the operator next to the API key. */
    let pubJwk = null, privJwk = null;
    try {
      const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
      pubJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
      privJwk = await crypto.subtle.exportKey('jwk', kp.privateKey);
    } catch { /* WIMSE keys are optional; registration works without them */ }

    const r = await jsonPost('/hhttps/machine/register', {
      operatorName: role || 'AI agent', purpose: role || 'AI/bot identity declaration',
      role: role || undefined, contactEmail: email, sessionId, publicKeyJwk: pubJwk || undefined
    });
    const d = await r.json().catch(() => ({})); if (!r.ok) { machineErr(d, r); return; }

    /* The machine path is SELF-CONTAINED: issue the machine token right away —
       it never goes through the human role/declare flow. */
    const r2 = await jsonPost('/hhttps/machine/token', { operatorId: d.operatorId, apiKey: d.apiKey });
    const td = await r2.json().catch(() => ({})); if (!r2.ok || !td.token) { machineErr(td, r2); return; }

    confirmed.machine = true; MACHINE_IDENTITY = true;
    $('m-machine').classList.add('done');
    $('st-machine').textContent = '🤖';
    $('machineEmail').style.display = 'none';
    $('machineCodeRow')?.classList.add('hidden');
    $('machineRole').style.display = 'none';
    $('machineGo').parentElement.style.display = 'none';
    hint.textContent = tr('machine.done');
    if (d.apiKey) {
      const k = $('machineKey'); k.style.display = 'block';
      k.textContent = tr('machine.key') + ' ' + d.apiKey
        + (privJwk ? ('\n\n' + tr('machine.privkey') + JSON.stringify(privJwk)) : '');
    }

    /* Publish the MACHINE identity — actorType bot, trustScore 0 (the rule). */
    storeIdentity(buildMachineIdentity(td, email), { actorType: 'bot' });

    const card = $('tokenCard'); card.classList.remove('hidden');
    const mth = document.querySelector('#tokenCard .h span[data-i18n]');
    if (mth) { mth.setAttribute('data-i18n', 'token.done.machine'); mth.textContent = tr('token.done.machine'); }
    $('tokenMethods').textContent = tr('token.machine.operator') + email;
    $('tokenRaw').textContent = shortToken(td.token);
    const ib = $('issueBtn'); if (ib) { ib.disabled = true; ib.style.display = 'none'; }
    card.scrollIntoView({ behavior: 'smooth', block: 'center' });
    maybeReturnTo();
  } catch { hint.textContent = tr('err'); }
}

/* ── Identity publication + OAuth return ────────────────────────────────────
   The OAuth consent page reads localStorage['hhttps_identity'] to find the
   signed-in human; without it, it bounces the user here with ?returnTo=<url>.
   After a token is issued we therefore (1) publish the identity in exactly the
   format the consent page and the browser extension expect (identity.js holds
   that schema), and (2) send the user back where they came from. */
function storeIdentity(identity, postPayload) {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(identity)); } catch { /* private mode */ }
  try {
    window.postMessage({ source: 'hhttps-org', type: 'identity-issued', payload: postPayload || identity },
      window.location.origin);
  } catch { /* postMessage is best effort */ }
}
function publishIdentity(d) {
  const h = (d && d.hhttps) || {};
  if (!h.token) return;
  const refresh = storableRefreshToken(h.refreshToken, h.refreshExpiresAt, window.location.hostname);
  storeIdentity(buildIdentity(d, methodsOf(), refresh));
}

/* Return to the OAuth consent page (or whoever sent us here). */
function maybeReturnTo() {
  let returnTo = null;
  try { returnTo = new URL(window.location.href).searchParams.get('returnTo'); } catch { return; }
  if (!returnTo) return;
  const target = resolveReturnTo(returnTo, window.location.origin);
  if (!target) return;
  const t = document.createElement('div');
  t.textContent = tr('return.toast') + target.host + ' …';
  t.style.cssText = 'position:fixed;top:20px;left:50%;transform:translateX(-50%);z-index:9999;'
    + 'background:#111;color:#fff;padding:12px 20px;border-radius:10px;font-weight:600;'
    + 'font-family:inherit;box-shadow:0 8px 30px rgba(0,0,0,.25);';
  document.body.appendChild(t);
  setTimeout(() => { window.location.href = target.href; }, 1200);
}

/* ISSUE TOKEN — role/declare {sessionId} once >=1 human method confirmed */
async function issueToken() {
  if (MACHINE_IDENTITY) return; // machine path issues its own token
  const btn = $('issueBtn'); btn.disabled = true;
  try {
    const r = await jsonPost('/hhttps/role/declare', { sessionId });
    const d = await r.json(); if (!r.ok) throw 0;
    const card = $('tokenCard'); card.classList.remove('hidden');
    $('tokenMethods').textContent = tr('token.methods') + methodsOf().join(' · ');
    const tok = d.hhttps && d.hhttps.token;
    if (tok) $('tokenRaw').textContent = shortToken(tok);
    publishIdentity(d);
    card.scrollIntoView({ behavior: 'smooth', block: 'center' });
    maybeReturnTo();
  } catch { btn.disabled = false; }
}

/* ── Section 2: professional role → iamhmn-card (esco/suggest + role/card) ───
   Real contracts only. role/card needs ≥1 verified method (ORDER), so the
   section is gated on hasAnyMethod(). RAL0 self-declared / RAL1 with proof;
   reserved professions block RAL0. RAL2 (qualified (Q)EAA / register) is the
   live target, honestly labelled, not faked here.

   AP8-37 (#226): the display list for the "request a qualification" chips.
   The AUTHORITATIVE registry is the server's RESERVED_REGISTRY
   (server/roles.taxonomy.js, echoed by GET /hhttps/roles); this list only adds
   the bilingual labels and the single ISCO-08 code the chip sends. A unit test
   pins the keys to the server registry so the two cannot drift apart. */
export const RESERVED = [
  { key: 'medical', de: 'Arzt / Ärztin', en: 'Doctor', isco08: '2212' },
  { key: 'nursing', de: 'Pflegefachkraft', en: 'Nurse', isco08: '2221' },
  { key: 'lawyer', de: 'Rechtsanwalt/-anwältin', en: 'Lawyer', isco08: '2611' },
  { key: 'notary', de: 'Notar/-in', en: 'Notary', isco08: '2619' },
  { key: 'police', de: 'Polizei', en: 'Police officer', isco08: '5412' },
  { key: 'judge', de: 'Richter/-in', en: 'Judge', isco08: '2612' }
];
let roleSel = null, qualSel = null;
const roleDocs = { self: false, qual: false };
let escoTimer = null;
function hasAnyMethod() { return ORDER.some((m) => confirmed[m]); }
function rolePick(which) {
  ['self', 'qual'].forEach((w) => {
    $('rb-' + w).classList.toggle('active', w === which);
    $('rolep-' + w).classList.toggle('hidden', w !== which);
  });
}
function renderQualChips() {
  const box = $('qualChips'); if (!box) return;
  box.textContent = '';
  RESERVED.forEach((r, i) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'role-chip' + (qualSel === i ? ' on' : '');
    b.textContent = LANG === 'de' ? r.de : r.en;
    b.addEventListener('click', () => qualPick(i));
    box.appendChild(b);
  });
}
function qualPick(i) { qualSel = i; renderQualChips(); refreshQual(); }
async function escoSuggest(text) {
  const list = $('escoList'); roleSel = null; refreshSelf();
  if (escoTimer) clearTimeout(escoTimer);
  if (text.trim().length < 2) { list.classList.add('hidden'); list.innerHTML = ''; return; }
  escoTimer = setTimeout(async () => {
    try {
      const r = await fetch(API + '/hhttps/esco/suggest?q=' + encodeURIComponent(text.trim()) + '&lang=' + LANG);
      const d = await r.json(); const hits = d.results || [];
      if (!hits.length) { list.classList.add('hidden'); list.innerHTML = ''; return; }
      list.innerHTML = hits.map((s, i) => `<div class="esco-item" data-esco="${i}">${s.reserved ? '🔒 ' : ''}<span>${escHtml(s.label)}</span>${s.isco08 ? `<span class="isco">ISCO ${escHtml(s.isco08)}</span>` : ''}</div>`).join('');
      list.querySelectorAll('[data-esco]').forEach((el) => {
        el.addEventListener('mousedown', () => escoPick(Number(el.getAttribute('data-esco'))));
      });
      list._hits = hits; list.classList.remove('hidden');
    } catch { list.classList.add('hidden'); }
  }, 180);
}
function escoPick(i) {
  const list = $('escoList'); const s = (list._hits || [])[i]; if (!s) return;
  roleSel = s; $('escoInput').value = s.label; escoHide(); refreshSelf();
}
function escoHide() { const l = $('escoList'); if (l) l.classList.add('hidden'); }
function roleFile(which, input) {
  const has = !!(input.files && input.files.length); roleDocs[which] = has;
  $(which === 'self' ? 'roleFileName' : 'qualFileName').textContent = has ? input.files[0].name : tr('role.file.none');
  if (which === 'self') refreshSelf(); else refreshQual();
}
function refreshSelf() {
  const q = $('escoInput').value.trim();
  const reserved = roleSel ? !!roleSel.reserved : false;
  const warn = $('roleWarnSelf'), go = $('roleGoSelf');
  if (reserved && !roleDocs.self) { warn.textContent = tr('role.hint.qual'); warn.hidden = false; go.disabled = true; return; }
  warn.hidden = true; go.disabled = q.length < 2;
}
function refreshQual() {
  const go = $('roleGoQual'), warn = $('roleWarnQual');
  if (qualSel === null) { go.disabled = true; return; }
  if (!roleDocs.qual) { warn.textContent = tr('role.hint.qual'); warn.hidden = false; go.disabled = true; return; }
  warn.hidden = true; go.disabled = false;
}
async function roleIssue(which) {
  const warn = $(which === 'self' ? 'roleWarnSelf' : 'roleWarnQual');
  const go = $(which === 'self' ? 'roleGoSelf' : 'roleGoQual');
  const result = $(which === 'self' ? 'roleResultSelf' : 'roleResultQual');
  if (!hasAnyMethod()) { warn.textContent = tr('role.needmethod'); warn.hidden = false; return; }
  go.disabled = true;
  const body = { sessionId, documentProvided: which === 'self' ? roleDocs.self : true };
  if (which === 'self') {
    if (roleSel) body.esco = { label: roleSel.label, isco08: roleSel.isco08, escoUri: roleSel.escoUri };
    else body.customRole = $('escoInput').value.trim();
  } else {
    const r = RESERVED[qualSel];
    body.esco = { label: LANG === 'de' ? r.de : r.en, isco08: r.isco08 };
  }
  try {
    const r = await jsonPost('/hhttps/role/card', body);
    const d = await r.json();
    if (!r.ok) { warn.textContent = d.remedy || d.error || tr('err'); warn.hidden = false; go.disabled = false; return; }
    warn.hidden = true;
    const ral = (d.card && d.card.ral) || 0, uri = d.offer && d.offer.uri, cross = (d.offer && d.offer.crossDeviceUri) || uri;
    let qrHtml = '';
    if (cross) {
      const qr = qrcode(0, 'L'); qr.addData(cross); qr.make();
      qrHtml = `<div class="qr" style="margin-top:14px"><div class="qr-frame"><span class="sp s1">✦</span><span class="sp s2">✦</span><span class="sp s3">✦</span><span class="sp s4">✦</span><img src="${qr.createDataURL(4, 8)}" alt="iamhmn-card QR"></div></div>`;
    }
    const ralLabel = ral >= 2 ? 'RAL 2' : (ral === 1 ? tr('role.ral1') : tr('role.ral0'));
    result.innerHTML = `<div class="ral-badge ral-${ral}"><span class="dot"></span><span>${escHtml(ralLabel)}</span></div>` + qrHtml + `<div class="ready">${escHtml(tr('role.ready'))}</div>` + (uri ? `<a class="openbtn" href="${escHtml(uri)}">${escHtml(tr('role.open'))}</a>` : '');
    go.disabled = false;
  } catch { warn.textContent = tr('err'); warn.hidden = false; go.disabled = false; }
}

/* ── Restore a previously issued identity across reloads ────────────────────
   The old sign-in page kept the token visible after a refresh. We restore it
   from localStorage; if the access token has expired we mint a fresh one from
   the refresh token, and only if that is impossible do we silently clear the
   stored identity and start over — the user never sees an "expired" error. */
function showTokenCard(identity) {
  try {
    const card = $('tokenCard');
    if (!card || !identity || !identity.token) return;
    const methods = (identity.method || '').split(',').filter(Boolean);
    let lbl = tr('token.methods') + (methods.join(' · ') || (identity.method || ''));
    const th = document.querySelector('#tokenCard .h span[data-i18n]');
    if (identity.actorType === 'bot') {
      lbl = tr('token.machine.operator') + (identity.operatorEmail || '');
      if (th) { th.setAttribute('data-i18n', 'token.done.machine'); th.textContent = tr('token.done.machine'); }
    } else if (th) { th.setAttribute('data-i18n', 'token.done'); th.textContent = tr('token.done'); }
    const mEl = $('tokenMethods'); if (mEl) mEl.textContent = lbl;
    const rEl = $('tokenRaw'); if (rEl) rEl.textContent = shortToken(identity.token);
    card.classList.remove('hidden');
  } catch { /* a broken stored record must not break the page */ }
}
async function restoreIdentity() {
  let identity = null;
  try { const raw = localStorage.getItem(STORAGE_KEY); if (raw) identity = JSON.parse(raw); } catch { /* ignore */ }
  if (!identity || !identity.token) return;

  const expired = jwtExp(identity.token) <= (Date.now() + 5000);
  if (expired) {
    // Try a stateless refresh; give up silently if not possible.
    let canRefresh = identity.refreshToken &&
      (!identity.refreshExpiresAt || new Date(identity.refreshExpiresAt).getTime() > Date.now());
    if (canRefresh) {
      try {
        const r = await jsonPost('/hhttps/token/refresh', { refreshToken: identity.refreshToken });
        if (r.ok) {
          const d = await r.json();
          if (d.token) {
            identity.token = d.token;
            identity.expiresAt = d.expiresAt || identity.expiresAt || null;
            /* AP3-18 (#116): /hhttps/token/refresh ROTATES the refresh token —
               every call returns a new one and invalidates the old one, and
               re-using an invalidated token trips the reuse detection. Storing
               only the new access token made the silent refresh work exactly
               once; the second attempt logged the user out. */
            if (d.refreshToken) {
              identity.refreshToken = storableRefreshToken(d.refreshToken,
                d.refreshExpiresAt || identity.refreshExpiresAt, window.location.hostname);
              identity.refreshExpiresAt = d.refreshExpiresAt || identity.refreshExpiresAt || null;
            }
            try { localStorage.setItem(STORAGE_KEY, JSON.stringify(identity)); } catch { /* ignore */ }
          } else { canRefresh = false; }
        } else { canRefresh = false; }
      } catch { canRefresh = false; }
    }
    if (!canRefresh) {
      try { localStorage.removeItem(STORAGE_KEY); } catch { /* ignore */ }
      return; // start fresh, no error surfaced
    }
  }
  showTokenCard(identity);
}

/* ── K-9: return from the magic link ──────────────────────────────────────
   GET /hhttps/email/verify redirects to
   /?email_verify=success&session=<id>&pseudonym=<p>&… (or
   ?email_verify=error&reason=<code>). Adopt the session, mark the email as
   confirmed (unlocking the other methods) and clean the URL afterwards. */
function cleanUrl(params) {
  try {
    const q = params.toString();
    history.replaceState(null, '', window.location.pathname + (q ? '?' + q : '') + window.location.hash);
  } catch { /* replaceState can fail on exotic origins */ }
}
function handleEmailVerifyReturn() {
  let params;
  try { params = new URLSearchParams(window.location.search); } catch { return; }
  const state = params.get('email_verify');
  if (!state) return;
  const hint = $('emailHint');
  if (state === 'success' && params.get('session')) {
    sessionId = params.get('session');
    markConfirmed('email');
    const pseudonym = (params.get('pseudonym') || '').toString();
    showPseudonym(pseudonym);
    if (hint) hint.textContent = tr('email.done').replace('{p}', pseudonym);
  } else if (state === 'error') {
    if (hint) hint.textContent = tr('err') + ' (' + (params.get('reason') || '') + ')';
    pick('email');
  }
  ['email_verify', 'session', 'pseudonym', 'reason', 'level', 'score', 'domain'].forEach((k) => params.delete(k));
  cleanUrl(params);
}

/* ── T9 / AK-31, AK-32: login_hint from the OAuth consent page ─────────────
   The consent page (relogin) sends a not-yet-signed-in user here as
   /?returnTo=<consent-url>&login_hint=<email>&pseudonym=<name>. Open the
   email panel, pre-fill both fields, strip login_hint/pseudonym from the URL
   (returnTo stays — maybeReturnTo() needs it) and request the code ONCE.
   Because the params are removed BEFORE the send, a reload never re-sends;
   an invalid address just leaves the pre-filled panel with a hint. */
function handleLoginHint() {
  let params;
  try { params = new URLSearchParams(window.location.search); } catch { return; }
  const loginHint = (params.get('login_hint') || '').trim();
  if (!loginHint) return;
  const pseudonym = (params.get('pseudonym') || '').trim();
  ['login_hint', 'pseudonym'].forEach((k) => params.delete(k));
  cleanUrl(params);
  pick('email');
  $('emailInput').value = loginHint;
  const pi = $('pseudoInput'); if (pi && pseudonym) pi.value = pseudonym;
  const hint = $('emailHint');
  if (!isEmail(loginHint)) { if (hint) hint.textContent = tr('err'); return; }
  if (hint) hint.textContent = tr('email.hintAuto');
  emailStart();
}

/* ── Event wiring ──────────────────────────────────────────────────────────
   AP8-34 (#215): replaces every `onclick=`/`oninput=`/`onchange=`/`onblur=`
   attribute that index.html used to carry. Keep this table in sync with the
   ids in the markup — the unit test asserts the page has no on*= attributes
   left and that every id referenced here exists. */
const CLICK_BINDINGS = {
  langBtn: toggleLang,
  'm-email': () => pick('email'),
  'm-passkey': () => pick('passkey'),
  'm-eudi': () => pick('eudi'),
  'm-age': () => pick('age'),
  'm-github': () => pick('github'),
  'm-machine': () => pick('machine'),
  emailSend: emailStart,
  emailVerify: emailConfirm,
  passkeyGo: passkeyRun,
  eudiGo: eudiRun,
  age14: () => ageRun(14),
  age16: () => ageRun(16),
  age18: () => ageRun(18),
  githubGo: githubRun,
  machineGo: machineRun,
  issueBtn: issueToken,
  'rb-self': () => rolePick('self'),
  'rb-qual': () => rolePick('qual'),
  roleGoSelf: () => roleIssue('self'),
  roleGoQual: () => roleIssue('qual')
};

function bindEvents() {
  for (const [id, fn] of Object.entries(CLICK_BINDINGS)) {
    const el = $(id);
    if (el) el.addEventListener('click', fn);
  }
  const esco = $('escoInput');
  if (esco) {
    esco.addEventListener('input', () => escoSuggest(esco.value));
    esco.addEventListener('blur', () => setTimeout(escoHide, 180));
  }
  const rf = $('roleFile'); if (rf) rf.addEventListener('change', () => roleFile('self', rf));
  const qf = $('qualFile'); if (qf) qf.addEventListener('change', () => roleFile('qual', qf));
}

bindEvents();
applyLang();
handleEmailVerifyReturn();
handleLoginHint();
restoreIdentity();
