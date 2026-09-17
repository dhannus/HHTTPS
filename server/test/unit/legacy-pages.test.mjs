// #27: the static landing page (../sites/hhttps.html) still talked to the
// pre-email-gate WebAuthn API and must use the email-first passkey flow
// (the Privacy Pass wallet was removed in the 2026-09 review, Welle 0):
//   session/start → email/send → email/confirm-code → register/start {sessionId}
//   → register/finish {userId, response, sessionId} → auth/start {userId}
//   → auth/finish {sessionId, response, priorSessionId}.
// There is no DOM here: the inline scripts are inspected with regexes and
// syntax-checked (through `new Function`).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const PAGES = {
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

// AP8-01 / AP8-41: /hhttps/role/declare answers `role: null` since v0.5, so the
// success path of doDeclarRole() must never dereference `d.role.<x>` without
// optional chaining — and there must be exactly one implementation (the former
// `window.doDeclarRole = …` override that shadowed a dead original is gone).
test('AP8-01 landing: doDeclarRole() is defined once and never reads d.role without `?.`', () => {
  const js = scriptText(PAGES.landing);
  const defs = js.match(/(?:async function doDeclarRole\s*\(|window\.doDeclarRole\s*=)/g) || [];
  assert.equal(defs.length, 1, `doDeclarRole is defined exactly once (found ${defs.length})`);
  assert.doesNotMatch(js, /origDeclare/, 'the dead origDeclare alias is gone');
  const body = fnBody(js, 'doDeclarRole');
  assert.doesNotMatch(body, /\bd\.role\.[A-Za-z_$]/, 'doDeclarRole never accesses d.role.<x> without `?.`');
  assert.doesNotMatch(body, /\bd\.role\[/, 'doDeclarRole never indexes d.role without `?.`');
  assert.ok(body.includes("'/hhttps/role/declare'"), 'doDeclarRole calls /hhttps/role/declare');
  assert.match(body, /d\.(verification|hhttps)\?\./, 'doDeclarRole reads d.verification / d.hhttps null-safely');
  assert.match(body, /setStep\(4\)/, 'success path reaches setStep(4)');
});
