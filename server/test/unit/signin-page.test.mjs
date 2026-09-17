// T7 / AK-14, AK-15: checks of the sign-in page.
//
// AP8-34 (#215): the page's 675-line inline <script> was moved into ES modules
// under public/js/signin/. Everything that used to be asserted by cutting the
// HTML with regexes is now asserted by IMPORTING those modules and calling
// them (see the second half of this file); only the checks that genuinely
// concern the markup — attributes, ids, data-i18n wiring, no inline handlers —
// still read index.html.
//
// #25: the BEHAVIOUR (AK-14 disabled buttons + unlock after confirm, AK-15
// pseudonym in /email/send and next to the check mark, K-9 magic-link return,
// K-7 "482 913" code input, passkey/K-4) is covered in the browser by
// test/e2e/signin.e2e.test.mjs (Playwright, `npm run test:e2e`).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { T, LANGS, tr } from '../../public/js/signin/i18n.js';
import {
  ISSUER, ISSUER_URL, STORAGE_KEY, isIssuerOrigin, storableRefreshToken,
  buildIdentity, buildMachineIdentity, resolveReturnTo
} from '../../public/js/signin/identity.js';
import { createPoller, POLL_START_MS, POLL_MAX_MS, POLL_MAX_TRIES } from '../../public/js/signin/poll.js';
import { escHtml, shortToken, jwtExp, normaliseCode, isEmail } from '../../public/js/signin/util.js';
import { RESERVED_REGISTRY } from '../../roles.taxonomy.js';

const here = dirname(fileURLToPath(import.meta.url));
const pub = (f) => readFileSync(join(here, '../../public/', f), 'utf8');
const html = pub('index.html');
const appSrc = pub('js/signin/app.js');

/** Body of `<div … id="panel-email">` up to the next method button. */
function emailPanel() {
  const start = html.indexOf('id="panel-email"');
  const end = html.indexOf('id="m-passkey"', start);
  assert.ok(start > 0 && end > start, 'email panel block is located before the passkey button');
  return html.slice(start, end);
}

// ── AP8-34: the page carries no JavaScript of its own any more ──────────────
test('AP8-34: index.html has no inline <script> and no on*= handler attributes', () => {
  assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/,
    'every <script> tag has a src — no inline script block is left');
  const handler = html.match(/\son[a-z]+\s*=\s*"/i);
  assert.equal(handler, null, `no inline event handler attributes (found ${handler && handler[0]})`);
  assert.match(html, /<script type="module" src="\/js\/signin\/app\.js"><\/script>/,
    'the sign-in module is loaded as a static ES module');
});

test('AP8-34: every element the module binds a click handler to exists in the page', () => {
  const block = appSrc.slice(appSrc.indexOf('const CLICK_BINDINGS'), appSrc.indexOf('function bindEvents'));
  const ids = [...block.matchAll(/^\s*'?([A-Za-z][\w-]*)'?\s*:/gm)].map((m) => m[1]);
  assert.ok(ids.length >= 20, `CLICK_BINDINGS covers the page buttons (${ids.length})`);
  for (const id of ids) {
    assert.ok(html.includes(`id="${id}"`), `#${id} exists in index.html`);
  }
  // The elements that used to carry oninput/onchange/onblur.
  for (const id of ['escoInput', 'roleFile', 'qualFile']) {
    assert.ok(html.includes(`id="${id}"`), `#${id} exists in index.html`);
    assert.ok(appSrc.includes(`$('${id}')`), `app.js wires #${id}`);
  }
});

test('AP8-33: Google Fonts is preconnected', () => {
  assert.match(html, /<link rel="preconnect" href="https:\/\/fonts\.googleapis\.com">/);
  assert.match(html, /<link rel="preconnect" href="https:\/\/fonts\.gstatic\.com" crossorigin>/);
  assert.match(html, /qrcode-generator@1\.4\.4\/qrcode\.js" defer/, 'vendor bundles are deferred');
});

// ── AK-15: optional pseudonym input in the email panel ──────────────────────
test('AK-15: pseudonym input lives in the email panel', () => {
  const panel = emailPanel();
  const m = panel.match(/<input\b[^>]*\bid="pseudoInput"[^>]*>/);
  assert.ok(m, '#pseudoInput exists inside #panel-email');
  const tag = m[0];
  assert.match(tag, /\btype="text"/, 'pseudoInput is a text input');
  assert.match(tag, /\bmaxlength="32"/, 'pseudoInput is limited to 32 chars');
  assert.match(tag, /\bautocomplete="nickname"/, 'pseudoInput uses autocomplete=nickname');
  assert.match(tag, /\bdata-i18n-ph="email\.pseudo\.ph"/, 'pseudoInput placeholder is i18n-driven');
  assert.ok(panel.indexOf('id="emailInput"') < panel.indexOf('id="pseudoInput"'), 'pseudonym field comes after the email field');
});

// ── K-7: code fields accept pasted "123 456" / "123-456" ────────────────────
test('K-7: #emailCode and #machineCode have no maxlength="6"', () => {
  for (const id of ['emailCode', 'machineCode']) {
    const m = html.match(new RegExp(`<input\\b[^>]*\\bid="${id}"[^>]*>`));
    assert.ok(m, `#${id} exists`);
    const ml = m[0].match(/\bmaxlength="(\d+)"/);
    if (ml) assert.ok(Number(ml[1]) >= 8, `#${id} maxlength is at least 8`);
  }
});

test('K-7: normaliseCode() strips the separators of a pasted code', () => {
  assert.equal(normaliseCode(' 482 913 '), '482913');
  assert.equal(normaliseCode('482-913'), '482913');
  assert.equal(normaliseCode(undefined), '');
});

// ── i18n ────────────────────────────────────────────────────────────────────
test('i18n: de and en carry exactly the same keys', () => {
  const de = Object.keys(T.de).sort(), en = Object.keys(T.en).sort();
  assert.deepEqual(de, en, 'no key exists in only one language');
  assert.deepEqual(LANGS, ['de', 'en']);
});

test('i18n: every key is used by the page or the module — and every used key exists', () => {
  const known = new Set(Object.keys(T.de));
  const used = new Set();
  for (const m of html.matchAll(/data-i18n(?:-ph)?="([^"]+)"/g)) used.add(m[1]);
  // Every single-quoted string in app.js that names a dictionary key: tr('x'),
  // setText(id, 'x'), the placeholder map and the data-i18n re-labelling.
  for (const m of appSrc.matchAll(/'([^'\n]+)'/g)) if (known.has(m[1])) used.add(m[1]);
  // The keys poll.js reports back by name rather than app.js naming them.
  for (const k of ['email.first', 'poll.failed', 'poll.expired', 'poll.timeout']) used.add(k);

  for (const m of appSrc.matchAll(/tr\('([^']+)'\)/g)) {
    assert.ok(known.has(m[1]), `tr('${m[1]}') names an existing dictionary key`);
  }
  for (const m of html.matchAll(/data-i18n(?:-ph)?="([^"]+)"/g)) {
    assert.ok(known.has(m[1]), `data-i18n="${m[1]}" names an existing dictionary key`);
  }
  for (const k of known) assert.ok(used.has(k), `dictionary key '${k}' is actually used`);
});

test('i18n: the required AK-15 / AK-31 / K-4 keys keep their contract', () => {
  for (const lang of LANGS) {
    for (const key of ['email.pseudo.ph', 'email.first', 'email.done']) {
      assert.ok(T[lang][key], `${lang} has '${key}'`);
    }
    assert.match(T[lang]['email.done'], /\{p\}/, `${lang} email.done contains the {p} placeholder`);
    assert.equal(T[lang]['email.pseudo.ph'], 'Pseudonym (optional)');
  }
  assert.match(T.de['email.first'], /^Zuerst E-Mail bestätigen/);
  assert.match(T.en['email.first'], /^Confirm your email first/);
  assert.equal(T.de['passkey.existing'], 'Passkey erkannt — bitte bestätigen');
  assert.equal(T.en['passkey.existing'], 'Passkey found — please confirm');
  assert.equal(T.de['email.hintAuto'], 'E-Mail übernommen — Code wird gesendet …');
  assert.equal(T.en['email.hintAuto'], 'Email taken over — sending code …');
});

test('i18n: tr() falls back to the key itself', () => {
  assert.equal(tr('de', 'issue.btn'), T.de['issue.btn']);
  assert.equal(tr('de', 'nope.nope'), 'nope.nope');
  assert.equal(tr('kl', 'issue.btn'), 'issue.btn');
});

// ── AP8-50: no bilingual ternaries left in the page code ────────────────────
test("AP8-50: app.js contains no LANG==='de' ? … : … text ternaries", () => {
  // Four legitimate uses stay, none of them a sentence: the EN/DE button
  // label, the toggle itself and the two RESERVED chip label lookups.
  const offenders = [...appSrc.matchAll(/LANG\s*===?\s*'de'\s*\?/g)];
  assert.equal(offenders.length, 4, 'only the label/data cases remain');
  assert.doesNotMatch(appSrc, /'Methoden: '/, 'token method prefix comes from the dictionary');
  assert.doesNotMatch(appSrc, /Angemeldet/, 'the return toast comes from the dictionary');
});

// ── AK-14 / flows: the module keeps the endpoint contracts ──────────────────
test('the module calls the email-first endpoint contract', () => {
  const call = (path) => {
    const at = appSrc.indexOf(`jsonPost('${path}'`);
    assert.ok(at > 0, `${path} is called`);
    return appSrc.slice(at, at + 260);
  };
  assert.match(call('/hhttps/webauthn/register/start'), /\{\s*sessionId\s*\}/,
    'register/start binds to the session (D4), not to a client-chosen userId');
  assert.match(call('/hhttps/webauthn/register/finish'), /userId:\s*pkUserId/);
  assert.match(call('/hhttps/webauthn/register/finish'), /\bsessionId\b/, '#23: register/finish carries the session');
  assert.match(call('/hhttps/webauthn/auth/start'), /userId:\s*pkUserId/);
  assert.match(call('/hhttps/webauthn/auth/finish'), /priorSessionId:\s*sessionId/);
  const pk = appSrc.slice(appSrc.indexOf('async function passkeyRun'), appSrc.indexOf('/* EUDI'));
  assert.ok(pk.indexOf('await ensureSession()') < pk.indexOf('/hhttps/webauthn/register/start'),
    'ensureSession() runs before register/start');
  assert.match(pk, /excludeCredentials/, 'K-4: passkeyRun inspects excludeCredentials');
  assert.match(pk, /InvalidStateError/, 'K-4: passkeyRun handles InvalidStateError');
  assert.match(pk, /tr\('passkey\.existing'\)/, "K-4: shows the 'passkey.existing' hint");
});

test('AK-31: handleLoginHint() cleans the URL before the auto-send and keeps returnTo', () => {
  const fn = appSrc.slice(appSrc.indexOf('function handleLoginHint'), appSrc.indexOf('/* ── Event wiring'));
  assert.match(fn, /params\.get\('login_hint'\)/);
  assert.match(fn, /params\.get\('pseudonym'\)/);
  assert.match(fn, /pick\('email'\)/);
  assert.match(fn, /tr\('email\.hintAuto'\)/);
  assert.match(fn, /tr\('err'\)/, 'AK-32: invalid address → err hint');
  assert.ok(fn.indexOf('cleanUrl(params)') < fn.indexOf('emailStart()'),
    'URL is cleaned BEFORE the auto-send (no loop on reload)');
  assert.doesNotMatch(fn, /params\.delete\('returnTo'\)/, 'returnTo is kept');
  assert.equal((appSrc.match(/^handleLoginHint\(\);$/gm) || []).length, 1, 'invoked exactly once at startup');
  assert.ok(appSrc.indexOf('\nhandleEmailVerifyReturn();') < appSrc.indexOf('\nhandleLoginHint();'));
});

test('AP8-13: emailStart() surfaces the EMAIL_DEV_MODE devCode', () => {
  const fn = appSrc.slice(appSrc.indexOf('async function emailStart'), appSrc.indexOf('async function emailConfirm'));
  assert.match(fn, /d\.devCode/, 'the dev code from /hhttps/email/send is shown');
});

// ── util.js ────────────────────────────────────────────────────────────────
test('util: escHtml escapes every dangerous character', () => {
  assert.equal(escHtml(`<a href="x">&'`), '&lt;a href=&quot;x&quot;&gt;&amp;&#39;');
  assert.equal(escHtml(null), 'null');
});

test('util: shortToken keeps header+payload and 16 signature characters', () => {
  assert.equal(shortToken('aa.bb.0123456789abcdefGHIJ'), 'aa.bb.0123456789abcdef…');
  assert.equal(shortToken('aa.bb'), 'aa.bb.…');
  assert.equal(shortToken(''), '');
  assert.equal(shortToken(null), '');
});

test('util: jwtExp reads exp in milliseconds and survives garbage', () => {
  const payload = Buffer.from(JSON.stringify({ exp: 1893456000 })).toString('base64url');
  assert.equal(jwtExp('h.' + payload + '.s'), 1893456000000);
  assert.equal(jwtExp('not-a-jwt'), 0);
  assert.equal(jwtExp(''), 0);
  const noExp = Buffer.from(JSON.stringify({ sub: 'x' })).toString('base64url');
  assert.equal(jwtExp('h.' + noExp + '.s'), 0);
});

test('util: isEmail accepts real addresses and rejects the obvious junk', () => {
  for (const ok of ['a@b.de', 'first.last+tag@sub.example.org']) assert.ok(isEmail(ok), ok);
  for (const bad of ['', 'a@b', 'a b@c.de', 'a@@b.de', 'nope', '@b.de']) assert.ok(!isEmail(bad), bad);
});

// ── identity.js — AP8-36: one schema, one writer ───────────────────────────
test('AP8-36: buildIdentity produces the documented hhttps_identity record', () => {
  const d = {
    hhttps: { token: 'h.p.s', trustScore: 42, expiresAt: '2030-01-01T00:00:00Z',
      refreshExpiresAt: '2030-02-01T00:00:00Z' },
    role: { id: 'dev', label: 'Developer', icon: '💻', level: 'ral1', levelLabel: 'RAL 1' }
  };
  const id = buildIdentity(d, ['email', 'passkey'], 'rt', '2026-09-17T00:00:00Z');
  assert.deepEqual(id, {
    token: 'h.p.s', refreshToken: 'rt', role: 'dev', roleLabel: 'Developer', roleIcon: '💻',
    roleLevel: 'ral1', levelLabel: 'RAL 1', trustScore: 42, actorType: 'human',
    method: 'email,passkey', verified_methods: ['email', 'passkey'],
    issuer: ISSUER, issuedAt: '2026-09-17T00:00:00Z',
    expiresAt: '2030-01-01T00:00:00Z', refreshExpiresAt: '2030-02-01T00:00:00Z'
  });
  assert.equal(STORAGE_KEY, 'hhttps_identity');
  assert.equal(ISSUER, 'hhttps://hhttps.org');
  assert.equal(ISSUER_URL, 'https://hhttps.org');
});

test("AP8-36: an identity without any method still reports 'email'", () => {
  const id = buildIdentity({ hhttps: { token: 't' } }, [], null);
  assert.equal(id.method, 'email');
  assert.deepEqual(id.verified_methods, []);
  assert.equal(id.role, null);
  assert.equal(id.trustScore, 0);
});

test('AP8-36: buildMachineIdentity is always a zero-trust bot record', () => {
  const id = buildMachineIdentity({ token: 'm.t.s', expiresAt: '2030-01-01T00:00:00Z' },
    'ops@example.org', '2026-09-17T00:00:00Z');
  assert.equal(id.actorType, 'bot');
  assert.equal(id.trustScore, 0);
  assert.equal(id.refreshToken, null, 'machines never hold a refresh token');
  assert.equal(id.method, 'machine');
  assert.deepEqual(id.verified_methods, ['machine']);
  assert.equal(id.operatorEmail, 'ops@example.org');
  assert.equal(id.roleIcon, '🤖');
  assert.equal(id.issuer, ISSUER);
});

test('AP8-36: the two producers agree on the field set (bar operatorEmail)', () => {
  const a = Object.keys(buildIdentity({ hhttps: { token: 't' } }, ['email'], null)).sort();
  const b = Object.keys(buildMachineIdentity({ token: 't' }, 'x@y.de')).filter((k) => k !== 'operatorEmail').sort();
  assert.deepEqual(a, b);
});

// ── AP8-20 (#173): refresh token only on the issuer origin, never expired ──
test('AP8-20: storableRefreshToken is origin- and expiry-gated', () => {
  const soon = new Date(Date.now() + 60000).toISOString();
  const past = new Date(Date.now() - 60000).toISOString();
  assert.equal(storableRefreshToken('rt', soon, 'hhttps.org'), 'rt');
  assert.equal(storableRefreshToken('rt', soon, 'www.hhttps.org'), 'rt');
  assert.equal(storableRefreshToken('rt', soon, 'localhost'), 'rt');
  assert.equal(storableRefreshToken('rt', null, '127.0.0.1'), 'rt');
  assert.equal(storableRefreshToken('rt', soon, 'evil.example'), null, 'foreign origin gets no refresh token');
  assert.equal(storableRefreshToken('rt', past, 'hhttps.org'), null, 'an expired refresh token is dropped');
  assert.equal(storableRefreshToken(null, soon, 'hhttps.org'), null);
  assert.ok(isIssuerOrigin('hhttps.org') && !isIssuerOrigin('hhttps.org.evil.example'));
});

// ── AP8-17 (#151): returnTo stays on this origin ───────────────────────────
test('AP8-17: resolveReturnTo only accepts same-origin targets', () => {
  const o = 'https://hhttps.org';
  assert.equal(resolveReturnTo('/oauth/consent?x=1', o).href, 'https://hhttps.org/oauth/consent?x=1');
  assert.equal(resolveReturnTo('https://hhttps.org/a', o).href, 'https://hhttps.org/a');
  for (const bad of ['//evil.example/x', 'https://evil.example/x', 'javascript:alert(1)',
    'data:text/html,x', '', null, 42]) {
    assert.equal(resolveReturnTo(bad, o), null, `rejected: ${bad}`);
  }
});

// ── poll.js — AP8-07 (#98): one poller, terminal states, cancellation ──────
function fakePoller(responses, opts) {
  let hidden = (opts && opts.hidden) || [];
  const slept = [];
  const p = createPoller({
    sleep: (ms) => { slept.push(ms); return Promise.resolve(); },
    isHidden: () => hidden.length > 0 && hidden.shift()
  });
  let i = 0;
  const fetchOnce = () => {
    const r = responses[Math.min(i++, responses.length - 1)];
    if (r === 'throw') return Promise.reject(new Error('net'));
    return Promise.resolve({ status: r.status || 200, json: () => Promise.resolve(r.body) });
  };
  return { poller: p, fetchOnce, slept, calls: () => i };
}

test('AP8-07: the poller stops on verified', async () => {
  const f = fakePoller([{ body: { status: 'pending' } }, { body: { status: 'verified' } }]);
  let got = null, msg = null;
  await f.poller.poll('eudi', f.fetchOnce, (d) => d.status === 'verified', (d) => { got = d; }, (k) => { msg = k; });
  assert.deepEqual(got, { status: 'verified' });
  assert.equal(msg, null);
  assert.equal(f.calls(), 2);
});

test('AP8-07: the poller stops on the e-mail gate, failed, expired and HTTP >= 400', async () => {
  const cases = [
    [{ body: { status: 'error', error: 'email_verification_required' } }, 'email.first'],
    [{ body: { status: 'failed' } }, 'poll.failed'],
    [{ body: { status: 'expired' } }, 'poll.expired'],
    [{ status: 503, body: { error: 'github_not_configured' } }, 'poll.failed']
  ];
  for (const [resp, expected] of cases) {
    const f = fakePoller([resp]);
    let msg = null;
    await f.poller.poll('x', f.fetchOnce, () => false, () => {}, (k) => { msg = k; });
    assert.equal(msg, expected, JSON.stringify(resp));
    assert.equal(f.calls(), 1, 'the loop ended after one request');
  }
});

test('AP8-07: the poller gives up after POLL_MAX_TRIES with a timeout hint', async () => {
  const f = fakePoller([{ body: { status: 'pending' } }]);
  let msg = null;
  await f.poller.poll('x', f.fetchOnce, () => false, () => {}, (k) => { msg = k; });
  assert.equal(msg, 'poll.timeout');
  assert.equal(f.calls(), POLL_MAX_TRIES);
  assert.equal(f.slept[0], POLL_START_MS);
  assert.equal(f.slept[f.slept.length - 1], POLL_MAX_MS, 'the interval grows up to the cap');
});

test('AP8-07: a hidden tab pauses without spending the budget', async () => {
  const f = fakePoller([{ body: { status: 'verified' } }], { hidden: [true, true] });
  let got = null;
  await f.poller.poll('x', f.fetchOnce, (d) => d.status === 'verified', (d) => { got = d; }, () => {});
  assert.ok(got, 'the run still completed');
  assert.equal(f.calls(), 1, 'the two hidden ticks issued no request');
});

test('AP8-07: starting a second run cancels the first', async () => {
  const f = fakePoller([{ body: { status: 'pending' } }]);
  let msg = null;
  const first = f.poller.poll('x', f.fetchOnce, () => false, () => {}, (k) => { msg = k; });
  f.poller.cancel('x');
  await first;
  assert.equal(msg, null, 'the cancelled run reports nothing');
});

test('AP8-07: a network error is not terminal', async () => {
  const f = fakePoller(['throw', 'throw', { body: { status: 'verified' } }]);
  let got = null;
  await f.poller.poll('x', f.fetchOnce, (d) => d.status === 'verified', (d) => { got = d; }, () => {});
  assert.ok(got, 'the poller kept going after two failed requests');
});

// ── AP8-37 (#226): the reserved chips cannot drift from the server registry ─
test('AP8-37: the page RESERVED list uses exactly the server registry keys', () => {
  // app.js binds DOM handlers on import, so the list is read from the source.
  const block = appSrc.slice(appSrc.indexOf('export const RESERVED = ['), appSrc.indexOf('];', appSrc.indexOf('export const RESERVED = [')));
  const chips = [...block.matchAll(/key:\s*'([^']+)'[\s\S]*?isco08:\s*'([^']+)'/g)]
    .map((m) => ({ key: m[1], isco08: m[2] }));
  assert.deepEqual(chips.map((c) => c.key).sort(), Object.keys(RESERVED_REGISTRY).sort(),
    'the client chip list and RESERVED_REGISTRY name the same professions');
  for (const c of chips) {
    const prefixes = RESERVED_REGISTRY[c.key].iscoPrefixes;
    assert.ok(prefixes.some((p) => c.isco08.startsWith(p)),
      `the ISCO code ${c.isco08} of '${c.key}' matches one of its server prefixes ${prefixes.join('/')}`);
  }
});
