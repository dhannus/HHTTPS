// T9 / AK-30: static checks of the consent page renderer (renderConsentPage
// in server.js is not exported — we inspect its source text). The behaviour
// over HTTP (params carried, relogin body) is covered by
// test/integration/login-hint.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const src = readFileSync(join(here, '../../server.js'), 'utf8');

/** Source of renderConsentPage(...) up to the next top-level function. */
function renderer() {
  const start = src.indexOf('function renderConsentPage(');
  assert.ok(start > 0, 'renderConsentPage is defined');
  // The renderer returns one template literal; it ends at the closing
  // </html> (the next top-level `function ` would be a false end, since the
  // inline consent script declares functions of its own).
  const end = src.indexOf('</html>', start);
  assert.ok(end > start, 'renderConsentPage ends with </html>');
  return src.slice(start, end);
}

test('AK-30: relogin() appends login_hint and pseudonym (URL-encoded) to the sign-in URL, keeping returnTo', () => {
  const fn = renderer().match(/function relogin\(\)\{([\s\S]*?)\n\}/);
  assert.ok(fn, 'relogin() exists in the consent page script');
  const body = fn[1];
  assert.match(body, /\?returnTo=' \+ encodeURIComponent\(window\.location\.href\)/, 'returnTo is still the consent URL');
  assert.match(body, /params\.get\('login_hint'\)/, 'login_hint read from params');
  assert.match(body, /params\.get\('pseudonym'\)/, 'pseudonym read from params');
  assert.match(body, /&login_hint=' \+ encodeURIComponent\(/, 'login_hint appended URL-encoded');
  assert.match(body, /&pseudonym=' \+ encodeURIComponent\(/, 'pseudonym appended URL-encoded');
});

test('AK-30: #pseudoInput is pre-filled via the DOM (platform hint or current name), never via HTML interpolation', () => {
  const r = renderer();
  const fn = r.match(/function openPseudoEdit\(prefill\)\{([\s\S]*?)\n\}/);
  assert.ok(fn, 'openPseudoEdit() exists');
  assert.match(fn[1], /getElementById\('pseudoInput'\)/, 'works on #pseudoInput');
  assert.match(fn[1], /pi\.value = prefill/, 'DOM pre-fill');
  assert.match(r, /const hint = params\.get\('pseudonym'\)/, 'the hint comes from params');
  assert.match(r, /openPseudoEdit\(hint\)/, 'a generated/absent name opens the field with the hint');
  const tag = r.match(/<input id="pseudoInput"[^>]*>/);
  assert.ok(tag, '#pseudoInput input exists');
  assert.doesNotMatch(tag[0], /value=/, 'no value attribute in the template');
  assert.doesNotMatch(tag[0], /\$\{/, 'no template interpolation in the input tag');
});

test('AK-33: the name box is hidden by default and only shown for a signed-in identity', () => {
  const r = renderer();
  assert.match(r, /<div class="pseudo-field" id="pseudoBox" hidden>/, '#pseudoBox starts hidden');
  assert.match(r, /<div class="pseudo-show" id="pseudoShow" hidden>/, 'read-only view starts hidden');
  assert.match(r, /<div id="pseudoEditBox" hidden>/, 'edit view starts hidden');
  assert.match(r, /if \(!ident \|\| !ident\.token\) return;/, 'no identity → box stays hidden (sign-in creates the account)');
  assert.match(r, /const GENERATED_PSEUDONYM = \/\^iamhmn_\[a-z0-9\]\{10\}\$\/;/, 'generated-name pattern matches AK-7');
  assert.match(r, /known && !GENERATED_PSEUDONYM\.test\(known\)/, 'a chosen name is shown read-only');
  assert.match(r, /getElementById\('pseudoName'\)\.textContent = known/, 'the name is set via textContent');
  assert.doesNotMatch(r, /pseudoName'\)\.innerHTML/, 'never via innerHTML');
  assert.match(r, /ident\.pseudonym \|\| \(jwtPayload\(ident\.token\) \|\| \{\}\)\.pseudonym/, 'remembered name wins over the token claim (AK-35)');
});

test('AK-34: approve sends set_pseudonym only after the user opened the field', () => {
  const r = renderer();
  const fn = r.match(/function pseudoPayload\(\)\{([\s\S]*?)\n\}/);
  assert.ok(fn, 'pseudoPayload() exists');
  assert.match(fn[1], /if \(!pseudoWanted\) return \{ pseudonym: null \};/, 'closed field → no name sent');
  assert.match(fn[1], /set_pseudonym: true/, 'open field with a value → set_pseudonym');
  const uses = r.match(/\.\.\.pseudoPayload\(\)/g) || [];
  assert.equal(uses.length, 2, 'both approve calls (first try + after refresh) use pseudoPayload()');
  assert.doesNotMatch(r, /pseudonym:\s+\(document\.getElementById\('pseudoInput'\)/, 'the raw field value is no longer sent unconditionally');
});

test('AK-35: the confirmed name is remembered in hhttps_identity before redirecting', () => {
  const r = renderer();
  assert.match(r, /rememberPseudonym\(d\.pseudonym\);\n {4}window\.location = d\.redirect;/, 'first try');
  assert.match(r, /rememberPseudonym\(d2\.pseudonym\); window\.location = d2\.redirect;/, 'after refresh');
});

test('AK-29: authorize reads login_hint/pseudonym and only adds valid values to the consent params', () => {
  const start = src.indexOf("app.get('/hhttps/oauth/authorize'");
  const end = src.indexOf("app.post('/hhttps/oauth/approve'", start);
  assert.ok(start > 0 && end > start, 'authorize route located');
  const route = src.slice(start, end);
  assert.match(route, /login_hint/, 'reads login_hint');
  assert.match(route, /sanitizePseudonym\(/, 'pseudonym goes through sanitizePseudonym');
  assert.match(route, /normalizeEmail\(/, 'login_hint goes through normalizeEmail');
  assert.match(route, /254/, 'login_hint length bounded to 254');
  assert.match(route, /params\.set\('login_hint'/, 'login_hint set conditionally on the params object');
  assert.match(route, /params\.set\('pseudonym'/, 'pseudonym set conditionally on the params object');
});
