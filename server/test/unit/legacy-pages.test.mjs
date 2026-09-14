// #27: the two legacy pages that still talked to the pre-email-gate WebAuthn
// API — the Privacy Pass wallet (privacy-pass/public/wallet.html, served under
// /privacy-pass/) and the static landing page (../sites/hhttps.html) — must use
// the email-first passkey flow:
//   session/start → email/send → email/confirm-code → register/start {sessionId}
//   → register/finish {userId, response, sessionId} → auth/start {userId}
//   → auth/finish {sessionId, response, priorSessionId}.
// There is no DOM here: the inline scripts are inspected with regexes and
// syntax-checked (the wallet script is an ES module, so it goes through
// `node --check --input-type=module`; the landing page script through
// `new Function`). The browser behaviour of the wallet is covered by
// test/e2e/wallet.e2e.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const PAGES = {
  wallet:  readFileSync(join(here, '../../privacy-pass/public/wallet.html'), 'utf8'),
  landing: readFileSync(join(here, '../../../sites/hhttps.html'), 'utf8'),
};

/** All inline (non-src) <script> bodies of a page, module or classic. */
function inlineScripts(html) {
  const out = [];
  const re = /<script(?![^>]*\bsrc=)([^>]*)>([\s\S]*?)<\/script>/g;
  let m;
  while ((m = re.exec(html))) out.push({ attrs: m[1], js: m[2] });
  assert.ok(out.length > 0, 'page has at least one inline script');
  return out;
}
const scriptText = (html) => inlineScripts(html).map((s) => s.js).join('\n');

/**
 * Every `JSON.stringify(...)` body argument that follows a fetch of `url`
 * (the first stringify within the next 600 characters of each occurrence).
 */
function bodiesFor(js, url) {
  const bodies = [];
  let idx = 0;
  for (;;) {
    const at = js.indexOf(`'${url}'`, idx);
    if (at < 0) break;
    idx = at + url.length;
    const window_ = js.slice(at, at + 600);
    const s = window_.indexOf('JSON.stringify(');
    assert.ok(s >= 0, `${url}: fetch call has a JSON.stringify body`);
    let depth = 0, i = s + 'JSON.stringify'.length, start = i + 1;
    for (; i < window_.length; i++) {
      if (window_[i] === '(') depth++;
      else if (window_[i] === ')' && --depth === 0) break;
    }
    bodies.push(window_.slice(start, i));
  }
  return bodies;
}

/** Body of a top-level `async function name(` / `window.name = async function (` block. */
function fnBody(js, name) {
  const re = new RegExp(`(?:async function ${name}\\s*\\(|window\\.${name}\\s*=\\s*async function\\s*\\()[\\s\\S]*?\\{`);
  const m = js.match(re);
  assert.ok(m, `${name}() is defined`);
  let depth = 0, i = m.index + m[0].length - 1;
  const start = i + 1;
  for (; i < js.length; i++) {
    if (js[i] === '{') depth++;
    else if (js[i] === '}' && --depth === 0) break;
  }
  return js.slice(start, i);
}

const hasSessionId = (body) => /(^|[{,\s])sessionId(\s*:\s*[A-Za-z_$][\w$.]*)?(\s*[,}]|\s*$)/.test(body);

for (const [name, html] of Object.entries(PAGES)) {
  const js = scriptText(html);

  test(`#27 ${name}: every register/start call sends sessionId (no more {userId}-only body)`, () => {
    const bodies = bodiesFor(js, '/hhttps/webauthn/register/start');
    assert.ok(bodies.length >= 1, 'register/start is called at least once');
    for (const b of bodies) {
      assert.ok(hasSessionId(b), `register/start body carries sessionId: ${b}`);
      assert.doesNotMatch(b.replace(/\s/g, ''), /^\{userId\}$/, `register/start body is not {userId}: ${b}`);
    }
  });

  test(`#27 ${name}: every register/finish call sends userId, response and sessionId`, () => {
    const bodies = bodiesFor(js, '/hhttps/webauthn/register/finish');
    assert.ok(bodies.length >= 1, 'register/finish is called at least once');
    for (const b of bodies) {
      assert.match(b, /\buserId\b/, `register/finish body carries userId: ${b}`);
      assert.match(b, /\bresponse\b/, `register/finish body carries response: ${b}`);
      assert.ok(hasSessionId(b), `register/finish body carries sessionId: ${b}`);
    }
  });

  test(`#27 ${name}: auth/finish merges the email session via priorSessionId`, () => {
    const bodies = bodiesFor(js, '/hhttps/webauthn/auth/finish');
    assert.ok(bodies.length >= 1, 'auth/finish is called at least once');
    assert.ok(bodies.some((b) => /\bpriorSessionId\b/.test(b)), `at least one auth/finish body carries priorSessionId: ${bodies.join(' | ')}`);
  });

  test(`#27 ${name}: email-first endpoints are used and the code is normalised`, () => {
    for (const url of ['/hhttps/session/start', '/hhttps/email/send', '/hhttps/email/confirm-code']) {
      assert.ok(js.includes(`'${url}'`), `${url} is called`);
    }
    for (const b of bodiesFor(js, '/hhttps/email/confirm-code')) {
      assert.ok(hasSessionId(b), `confirm-code body carries sessionId: ${b}`);
      assert.match(b, /\bcode\b/, `confirm-code body carries code: ${b}`);
    }
    assert.ok(js.includes(".replace(/[\\s-]/g,'')") || js.includes('.replace(/[\\s-]/g, \'\')'),
      'the entered code is normalised with .replace(/[\\s-]/g,\'\')');
  });

  test(`#27 ${name}: register/start handles excludeCredentials / InvalidStateError (returning passkey user)`, () => {
    assert.match(js, /excludeCredentials/, 'excludeCredentials from register/start is inspected');
    assert.match(js, /InvalidStateError/, 'InvalidStateError from startRegistration is handled');
  });
}

// ── wallet specifics ──
test('#27 wallet: doLogin, registerNewCredential and addCredential await the session + email helpers before register/start', () => {
  const js = scriptText(PAGES.wallet);
  assert.match(js, /async function ensureHhttpsSession\s*\(/, 'ensureHhttpsSession() is defined');
  assert.match(js, /async function ensureEmailVerified\s*\(/, 'ensureEmailVerified() is defined');
  assert.ok(js.includes("'/hhttps/email/status'"), 'ensureEmailVerified checks /hhttps/email/status');
  for (const name of ['doLogin', 'registerNewCredential', 'addCredential']) {
    const body = fnBody(js, name);
    // register/start is issued either inline or through the registerStart()
    // helper (which carries the 403 email_verification_required retry).
    const reg = Math.max(body.indexOf('/hhttps/webauthn/register/start'), body.indexOf('registerStart()'), body.indexOf('registerPasskey()'));
    assert.ok(reg >= 0, `${name} calls register/start (directly, via registerStart() or via registerPasskey())`);
    const s = body.indexOf('await ensureHhttpsSession()');
    const e = body.indexOf('await ensureEmailVerified()');
    assert.ok(s >= 0 && s < reg, `${name} awaits ensureHhttpsSession() before register/start`);
    assert.ok(e >= 0 && e < reg, `${name} awaits ensureEmailVerified() before register/start`);
  }
  const login = fnBody(js, 'doLogin');
  const rs = fnBody(js, 'registerStart');
  assert.match(rs, /email_verification_required/, 'registerStart() retries through ensureEmailVerified() on the 403 gate');
  assert.match(rs, /await ensureEmailVerified\(\)/, 'registerStart() awaits ensureEmailVerified() on the gate');
  assert.match(login, /priorSessionId\s*:\s*sessionId/, 'doLogin merges the email session on auth/finish');
});

test('#27 wallet: the auth card has the inline email dialog and the i18n keys exist in de and en', () => {
  const html = PAGES.wallet;
  const start = html.indexOf('id="card-auth"');
  const end = html.indexOf('id="card-creds"', start);
  assert.ok(start > 0 && end > start, 'auth card located');
  const card = html.slice(start, end);
  for (const id of ['auth-email-area', 'auth-email-input', 'btn-auth-email-send', 'auth-email-code', 'btn-auth-email-confirm']) {
    assert.match(card, new RegExp(`\\bid="${id}"`), `#${id} is inside #card-auth`);
  }
  const code = card.match(/<input\b[^>]*\bid="auth-email-code"[^>]*>/)[0];
  const ml = code.match(/\bmaxlength="(\d+)"/);
  if (ml) assert.ok(Number(ml[1]) >= 8, '#auth-email-code accepts "482 913" (maxlength >= 8)');

  for (const lang of ['de', 'en']) {
    const m = html.match(new RegExp(`\\n\\s*${lang}:\\s*\\{([\\s\\S]*?)\\n\\s*\\}`));
    assert.ok(m, `T.${lang} block exists`);
    for (const key of ['js.emailFirst', 'js.emailSend', 'js.emailCode', 'js.emailConfirm', 'js.emailOk']) {
      assert.ok(m[1].includes(`"${key}":`), `T.${lang} has "${key}"`);
    }
  }
});

test('#27 wallet: inline module script parses (node --check --input-type=module)', () => {
  const mod = inlineScripts(PAGES.wallet).find((s) => /type="module"/.test(s.attrs));
  assert.ok(mod, 'wallet has an inline module script');
  const r = spawnSync(process.execPath, ['--check', '--input-type=module'], { input: mod.js, encoding: 'utf8' });
  assert.equal(r.status, 0, `module script compiles:\n${r.stderr}`);
});

// ── landing page specifics ──
test('#27 landing: email step comes first; doRegister/doAuth use the session flow', () => {
  const html = PAGES.landing;
  const js = scriptText(html);
  assert.ok(html.indexOf('id="p0"') > 0 && html.indexOf('id="p0"') < html.indexOf('id="p1"'), 'phase p0 (email) precedes p1 (passkey)');
  assert.match(js, /function setStep\(n\)\s*\{\s*\[0,\s*1,\s*2,\s*3,\s*4\]/, 'setStep() knows step 0');
  const send = fnBody(js, 'doSendEmail');
  assert.ok(send.includes("'/hhttps/email/send'"), 'doSendEmail calls /hhttps/email/send');
  assert.doesNotMatch(send, /msg\.doWebauthn/, 'doSendEmail no longer requires a passkey session first');
  const confirm = fnBody(js, 'doConfirmEmail');
  assert.ok(confirm.includes("'/hhttps/email/confirm-code'"), 'doConfirmEmail calls /hhttps/email/confirm-code');
  assert.match(confirm, /localStorage\.setItem\('hhttps_uid'/, 'the stable userId from confirm-code is cached');
  const reg = fnBody(js, 'doRegister');
  assert.ok(reg.indexOf('ensureSession()') >= 0 && reg.indexOf('ensureSession()') < reg.indexOf('/hhttps/webauthn/register/start'),
    'doRegister ensures a session before register/start');
  assert.doesNotMatch(js, /devToken/, 'legacy devToken auto-verify is gone');
  assert.doesNotMatch(js, /\/hhttps\/email\/verify\?token=/, 'legacy /hhttps/email/verify?token= call is gone');
});

test('#27 landing: inline scripts parse (new Function)', () => {
  for (const { js } of inlineScripts(PAGES.landing)) {
    assert.doesNotThrow(() => new Function(js), 'inline script compiles');
  }
});
