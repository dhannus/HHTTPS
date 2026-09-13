// T7 / AK-14, AK-15: static checks of the sign-in page (public/index.html).
// The page is plain HTML with one inline script; there is no DOM here, so we
// check attributes and strings with regexes and syntax-check the script by
// compiling it with `new Function` (never executed).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const html = readFileSync(join(here, '../../public/index.html'), 'utf8');

/** Opening `<button …>` tag whose attributes contain id="<id>". */
function openingTag(id) {
  const m = html.match(new RegExp(`<button\\b[^>]*\\bid="${id}"[^>]*>`));
  assert.ok(m, `opening <button> tag with id="${id}" exists`);
  return m[0];
}

/** Inner text of the inline (non-src) <script> block. */
function inlineScript() {
  const m = html.match(/<script>([\s\S]*?)<\/script>/);
  assert.ok(m, 'inline <script> block exists');
  return m[1];
}

/** Body of `<div … id="panel-email">` up to the next method button. */
function emailPanel() {
  const start = html.indexOf('id="panel-email"');
  const end = html.indexOf('id="m-passkey"', start);
  assert.ok(start > 0 && end > start, 'email panel block is located before the passkey button');
  return html.slice(start, end);
}

/** i18n dictionary block for one language (T.de / T.en). */
function i18nBlock(lang) {
  const re = new RegExp(`\\b${lang}:\\{([\\s\\S]*?)\\}\\s*[,}]\\s*(?:en:|;)`);
  const m = html.match(re);
  assert.ok(m, `i18n block for ${lang} exists`);
  return m[1];
}

// ── AK-14: email first — the other human methods are disabled until confirmed ──
test('AK-14: passkey, eudi, github, age buttons are rendered disabled and gated on email', () => {
  for (const x of ['passkey', 'eudi', 'github', 'age']) {
    const tag = openingTag(`m-${x}`);
    assert.match(tag, /(^|\s)disabled(\s|>)/, `#m-${x} has the disabled attribute`);
    assert.match(tag, /\sdata-requires-email="true"/, `#m-${x} has data-requires-email="true"`);
  }
});

test('AK-14: email and machine buttons are NOT gated', () => {
  for (const x of ['email', 'machine']) {
    const tag = openingTag(`m-${x}`);
    assert.doesNotMatch(tag, /(^|\s)disabled(\s|>)/, `#m-${x} must not be disabled`);
    assert.doesNotMatch(tag, /data-requires-email/, `#m-${x} must not carry data-requires-email`);
  }
});

test('AK-14: persistent "email first" hint exists and the script unlocks gated buttons', () => {
  assert.ok(html.includes('id="emailFirstHint"'), 'hint element #emailFirstHint exists');
  const js = inlineScript();
  assert.match(js, /querySelectorAll\(\s*['"`][^'"`]*data-requires-email[^'"`]*['"`]\s*\)/,
    'script selects [data-requires-email] buttons via querySelectorAll');
  assert.match(js, /removeAttribute\(\s*['"]disabled['"]\s*\)/, 'script removes the disabled attribute');
});

test('AK-14: pick() bails out on a disabled method button and shows the email-first hint', () => {
  const js = inlineScript();
  const pick = js.match(/function pick\(m\)\{([\s\S]*?)\n\}/);
  assert.ok(pick, 'pick(m) is defined');
  assert.match(pick[1], /disabled/, 'pick() checks the disabled state');
  assert.match(pick[1], /tr\(\s*'email\.first'\s*\)/, "pick() uses the 'email.first' text");
});

// ── AK-15: optional pseudonym input in the email panel, sent with /email/send ──
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

test('AK-15: emailStart() sends pseudonym with /hhttps/email/send', () => {
  const js = inlineScript();
  const fn = js.match(/async function emailStart\(\)\{([\s\S]*?)\n\}/);
  assert.ok(fn, 'emailStart() is defined');
  const call = fn[1].match(/\/hhttps\/email\/send'[^\n]*body:JSON\.stringify\(([^\n]*?)\)\}\)/);
  assert.ok(call, 'emailStart posts to /hhttps/email/send with a JSON body');
  assert.match(call[1], /pseudonym/, 'the /email/send body includes pseudonym');
  assert.match(fn[1], /pseudoInput/, 'emailStart reads #pseudoInput');
});

test('AK-15: applyLang() sets the pseudonym placeholder', () => {
  const js = inlineScript();
  const fn = js.match(/function applyLang\(\)\{([\s\S]*?)\n\}/);
  assert.ok(fn, 'applyLang() is defined');
  assert.match(fn[1], /email\.pseudo\.ph/, 'applyLang sets the pseudoInput placeholder');
});

// ── Pseudonym display after confirm-code ──
test('after confirm-code the pseudonym is shown next to the check mark', () => {
  const js = inlineScript();
  const fn = js.match(/async function emailConfirm\(\)\{([\s\S]*?)\n\}/);
  assert.ok(fn, 'emailConfirm() is defined');
  assert.match(fn[1], /pseudonym/, 'emailConfirm reads the pseudonym from the response');
  assert.match(fn[1], /email\.done/, "emailConfirm uses the 'email.done' hint");
  assert.match(js, /class(?:Name)?=['"]pseudo['"]/, 'a .pseudo span is rendered into the state slot');
});

// ── Passkey: register/start binds to the session (D4), not to a client-chosen userId ──
test('passkeyRun() calls register/start with {sessionId} after ensureSession()', () => {
  const js = inlineScript();
  const fn = js.match(/async function passkeyRun\(\)\{([\s\S]*?)\n\}/);
  assert.ok(fn, 'passkeyRun() is defined');
  const body = fn[1];
  const call = body.match(/\/hhttps\/webauthn\/register\/start'[^\n]*body:JSON\.stringify\(([^\n]*?)\)\}\)/);
  assert.ok(call, 'register/start is called with a JSON body');
  assert.match(call[1], /\bsessionId\b/, 'register/start body carries sessionId');
  assert.doesNotMatch(body, /pkUserId\?\{userId:pkUserId\}:\{\}/, 'legacy pkUserId-or-empty body is gone');
  assert.ok(body.indexOf('await ensureSession()') >= 0, 'passkeyRun awaits ensureSession()');
  assert.ok(body.indexOf('await ensureSession()') < body.indexOf('/hhttps/webauthn/register/start'),
    'ensureSession() runs before register/start');
  assert.match(body, /pkUserId=ro\.userId/, 'pkUserId is still taken from the register/start response for auth/start');
});

// ── i18n keys ──
test('i18n: email.pseudo.ph, email.first, email.done exist in de and en', () => {
  for (const lang of ['de', 'en']) {
    const block = i18nBlock(lang);
    for (const key of ['email.pseudo.ph', 'email.first', 'email.done']) {
      assert.match(block, new RegExp(`'${key.replace('.', '\\.')}':`), `${lang} has '${key}'`);
    }
    assert.match(block, /'email\.done':'[^']*\{p\}/, `${lang} email.done contains the {p} placeholder`);
  }
  assert.match(i18nBlock('de'), /'email\.pseudo\.ph':'Pseudonym \(optional\)'/);
  assert.match(i18nBlock('en'), /'email\.pseudo\.ph':'Pseudonym \(optional\)'/);
  assert.match(i18nBlock('de'), /'email\.first':'Zuerst E-Mail bestätigen/);
  assert.match(i18nBlock('en'), /'email\.first':'Confirm your email first/);
});

// ── Header comment reflects the email-first rule ──
test('script header no longer claims four equal entry methods', () => {
  const js = inlineScript();
  assert.doesNotMatch(js, /FOUR EQUAL entry methods/);
  assert.match(js, /[Ee]-?[Mm]ail first/i, 'header explains the email-first rule');
});

// ── F-9 / K-4: returning passkey user — skip registration when credentials exist ──
test('K-4: passkeyRun() skips register/finish when excludeCredentials is non-empty or InvalidStateError', () => {
  const js = inlineScript();
  const fn = js.match(/async function passkeyRun\(\)\{([\s\S]*?)\n\}/);
  assert.ok(fn, 'passkeyRun() is defined');
  const body = fn[1];
  assert.match(body, /excludeCredentials/, 'passkeyRun inspects ro.options.excludeCredentials');
  assert.match(body, /InvalidStateError/, 'passkeyRun handles InvalidStateError from startRegistration');
  assert.match(body, /tr\(\s*'passkey\.existing'\s*\)/, "passkeyRun shows the 'passkey.existing' hint");
  const auth = body.match(/\/hhttps\/webauthn\/auth\/start'[^\n]*body:JSON\.stringify\(([^\n]*?)\)\}\)/);
  assert.ok(auth, 'auth/start is called with a JSON body');
  assert.match(auth[1], /userId/, 'auth/start body carries userId');
  const fin = body.match(/\/hhttps\/webauthn\/auth\/finish'[^\n]*body:JSON\.stringify\(([^\n]*?)\)\}\)/);
  assert.ok(fin, 'auth/finish is called with a JSON body');
  assert.match(fin[1], /priorSessionId:sessionId/, 'auth/finish merges the prior session');
});

test('K-4: i18n passkey.existing exists in de and en', () => {
  assert.match(i18nBlock('de'), /'passkey\.existing':'Passkey erkannt — bitte bestätigen'/);
  assert.match(i18nBlock('en'), /'passkey\.existing':'Passkey found — please confirm'/);
});

// ── F-9 / K-9: magic-link return (?email_verify=success&session=…&pseudonym=…) ──
test('K-9: page evaluates email_verify query params on load and cleans the URL', () => {
  const js = inlineScript();
  assert.match(js, /URLSearchParams/, 'script uses URLSearchParams');
  assert.match(js, /email_verify/, 'script reads the email_verify param');
  assert.match(js, /['"]success['"]/, 'script handles email_verify=success');
  assert.match(js, /['"]error['"]/, 'script handles email_verify=error');
  assert.match(js, /['"]pseudonym['"]/, 'script reads the pseudonym param');
  assert.match(js, /['"]reason['"]/, 'script reads the reason param');
  assert.match(js, /markConfirmed\(\s*'email'\s*\)/, 'script marks email confirmed');
  assert.match(js, /history\.replaceState/, 'script strips the query params via history.replaceState');
});

// ── F-9 / K-7: code fields accept pasted "123 456" / "123-456" ──
test('K-7: #emailCode and #machineCode have no maxlength="6"; codes are normalised before sending', () => {
  for (const id of ['emailCode', 'machineCode']) {
    const m = html.match(new RegExp(`<input\\b[^>]*\\bid="${id}"[^>]*>`));
    assert.ok(m, `#${id} exists`);
    assert.doesNotMatch(m[0], /\bmaxlength="6"/, `#${id} has no maxlength="6"`);
    const ml = m[0].match(/\bmaxlength="(\d+)"/);
    if (ml) assert.ok(Number(ml[1]) >= 8, `#${id} maxlength is at least 8`);
  }
  const js = inlineScript();
  const ec = js.match(/async function emailConfirm\(\)\{([\s\S]*?)\n\}/);
  assert.ok(ec, 'emailConfirm() is defined');
  assert.ok(ec[1].includes(".replace(/[\\s-]/g,'')"), 'emailConfirm normalises the code');
  const mr = js.match(/async function machineRun\(\)\{([\s\S]*?)\n\}/);
  assert.ok(mr, 'machineRun() is defined');
  assert.ok(mr[1].includes(".replace(/[\\s-]/g,'')"), 'machineRun normalises the code');
});

// ── Syntax check of the inline script (compiled, never executed) ──
test('inline script parses as JavaScript', () => {
  const js = inlineScript();
  assert.doesNotThrow(() => new Function(js), 'inline script compiles');
});

// ── #23: register/finish is bound to the email-verified session ──
test('#23: passkeyRun() sends sessionId with /hhttps/webauthn/register/finish', () => {
  const js = inlineScript();
  const fn = js.match(/async function passkeyRun\(\)\{([\s\S]*?)\n\}/);
  assert.ok(fn, 'passkeyRun() is defined');
  const body = fn[1];
  const call = body.match(/\/hhttps\/webauthn\/register\/finish'[^\n]*body:JSON\.stringify\(([^\n]*?)\)\}\)/);
  assert.ok(call, 'register/finish is called with a JSON body');
  assert.match(call[1], /\buserId\s*:\s*pkUserId\b/, 'register/finish body carries userId: pkUserId');
  assert.match(call[1], /\bresponse\s*:\s*regResp\b/, 'register/finish body carries response: regResp');
  assert.match(call[1], /(^|[{,\s])sessionId(\s*:\s*sessionId)?(\s*[,}]|$)/, 'register/finish body carries sessionId');
});
